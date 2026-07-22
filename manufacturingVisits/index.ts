import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyTeamsToken, AuthError, type Caller } from "../_shared/teamsAuth.ts";

/**
 * /events — the only door into the database.
 *
 * The tab never holds a database credential. It holds a Microsoft token that
 * proves who the user is; this function checks that token, then does the work
 * with the secret key. That key never leaves the server.
 */

const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";

const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Vary": "Origin",
};

/**
 * Supabase is mid-migration from anon/service_role to publishable/secret keys.
 * New projects only get the new ones. Read whichever this project has.
 */
function secretKey(): string {
  const bundle = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (bundle) {
    try {
      const parsed = JSON.parse(bundle);
      if (parsed.default) return parsed.default;
      const first = Object.values(parsed)[0];
      if (typeof first === "string") return first;
    } catch { /* fall through to the legacy variable */ }
  }
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!legacy) throw new Error("No Supabase secret key available to the function");
  return legacy;
}

const db = createClient(Deno.env.get("SUPABASE_URL")!, secretKey(), {
  auth: { persistSession: false },
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

/* ---------------------------------------------------------------- *
 * Validation. Everything below this line came from a browser, so
 * none of it is trusted until it has been through here.
 * ---------------------------------------------------------------- */
const SCOPE_KINDS = ["channel", "chat", "personal", "org"];
const CATEGORIES = ["purple", "teal", "coral", "amber", "green", "slate"];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^\d{2}:\d{2}$/;

class BadRequest extends Error {}

function cleanEvent(input: Record<string, unknown>) {
  const title = String(input.title ?? "").trim();
  if (!title) throw new BadRequest("Title is required");
  if (title.length > 200) throw new BadRequest("Title is too long");

  const date = String(input.date ?? "");
  if (!DATE_RE.test(date)) throw new BadRequest("Date must be YYYY-MM-DD");

  // Optional end date for multi-day events. Absent/equal means a single day.
  let endDate = input.endDate ? String(input.endDate) : null;
  if (endDate) {
    if (!DATE_RE.test(endDate)) throw new BadRequest("End date must be YYYY-MM-DD");
    if (endDate < date) throw new BadRequest("End date is before the start date");
    if (endDate === date) endDate = null; // store single-day events with no range
  }

  const allDay = Boolean(input.allDay);
  const start = input.start ? String(input.start) : null;
  const end = input.end ? String(input.end) : null;

  if (!allDay) {
    if (!start || !TIME_RE.test(start)) throw new BadRequest("Start time must be HH:MM");
    if (end && !TIME_RE.test(end)) throw new BadRequest("End time must be HH:MM");
    if (end && end < start) throw new BadRequest("Event ends before it starts");
  }

  const category = String(input.category ?? "purple");
  if (!CATEGORIES.includes(category)) throw new BadRequest("Unknown category");

  const notes = String(input.notes ?? "");
  if (notes.length > 2000) throw new BadRequest("Notes are too long");

  return {
    title,
    event_date: date,
    end_date: endDate,
    all_day: allDay,
    start_time: allDay ? null : start,
    end_time: allDay ? null : end,
    category,
    notes,
  };
}

/** Database row -> the shape the calendar component already speaks. */
const toClient = (row: Record<string, any>) => ({
  id: row.id,
  title: row.title,
  date: row.event_date,
  endDate: row.end_date || row.event_date,
  start: row.start_time ? row.start_time.slice(0, 5) : "",
  end: row.end_time ? row.end_time.slice(0, 5) : "",
  allDay: row.all_day,
  category: row.category,
  notes: row.notes ?? "",
});

/**
 * Find or create the calendar for a scope.
 *
 * For "org" the scope id is the tenant itself, taken from the signed token —
 * so every user in the organization resolves to the one same calendar, and
 * there's nothing a client could pass to reach a different org's data.
 */
async function resolveCalendar(caller: Caller, kind: string, id: string) {
  if (!SCOPE_KINDS.includes(kind)) throw new BadRequest("Unknown scope kind");
  // "personal" and "org" derive their scope id from the token, not the request,
  // so neither can be spoofed. Only channel/chat read the client-supplied id.
  const scopeId = kind === "personal"
    ? caller.userId
    : kind === "org"
    ? caller.tenantId
    : String(id ?? "");
  if (!scopeId) throw new BadRequest("Missing scope id");

  const { data, error } = await db
    .from("calendars")
    .upsert(
      { tenant_id: caller.tenantId, scope_kind: kind, scope_id: scopeId },
      { onConflict: "tenant_id,scope_kind,scope_id", ignoreDuplicates: false },
    )
    .select("id")
    .single();

  if (error) throw error;
  return data.id as string;
}

/** Confirm an event belongs to a calendar this caller's tenant owns. */
async function assertOwnership(caller: Caller, eventId: string) {
  const { data, error } = await db
    .from("events")
    .select("id, calendars!inner(tenant_id)")
    .eq("id", eventId)
    .single();

  if (error || !data) throw new BadRequest("Event not found");
  if ((data as any).calendars.tenant_id !== caller.tenantId) {
    throw new AuthError("Event belongs to another tenant");
  }
}

/* ---------------------------------------------------------------- *
 * Router
 * ---------------------------------------------------------------- */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  try {
    const caller = await verifyTeamsToken(req.headers.get("Authorization"));
    const url = new URL(req.url);
    // Path is /events or /events/<uuid>
    const eventId = url.pathname.split("/").filter(Boolean).pop();
    const hasId = eventId && eventId !== "events";

    if (req.method === "GET") {
      const kind = url.searchParams.get("scopeKind") ?? "";
      const scopeId = url.searchParams.get("scopeId") ?? "";
      const from = url.searchParams.get("from") ?? "";
      const to = url.searchParams.get("to") ?? "";
      if (!DATE_RE.test(from) || !DATE_RE.test(to)) {
        throw new BadRequest("from and to must be YYYY-MM-DD");
      }

      const calendarId = await resolveCalendar(caller, kind, scopeId);
      // An event is in range if it overlaps the window at all: it starts on or
      // before the window end, AND its end (or its start, if single-day) is on
      // or after the window start. This catches multi-day events whose start
      // falls before `from` but which still run into the window.
      const { data, error } = await db
        .from("events")
        .select("*")
        .eq("calendar_id", calendarId)
        .lte("event_date", to)
        .or(`end_date.gte.${from},and(end_date.is.null,event_date.gte.${from})`)
        .order("event_date")
        .order("start_time", { nullsFirst: true });

      if (error) throw error;
      return json({ events: data.map(toClient) });
    }

    if (req.method === "POST") {
      const body = await req.json();
      const calendarId = await resolveCalendar(
        caller, body?.scope?.kind, body?.scope?.id,
      );
      const { data, error } = await db
        .from("events")
        .insert({
          ...cleanEvent(body.event ?? {}),
          calendar_id: calendarId,
          created_by: caller.userId,
        })
        .select("*")
        .single();

      if (error) throw error;
      return json({ event: toClient(data) }, 201);
    }

    if (req.method === "PATCH") {
      if (!hasId) throw new BadRequest("Missing event id");
      await assertOwnership(caller, eventId!);
      const body = await req.json();
      const { data, error } = await db
        .from("events")
        .update(cleanEvent(body.event ?? {}))
        .eq("id", eventId)
        .select("*")
        .single();

      if (error) throw error;
      return json({ event: toClient(data) });
    }

    if (req.method === "DELETE") {
      if (!hasId) throw new BadRequest("Missing event id");
      await assertOwnership(caller, eventId!);
      const { error } = await db.from("events").delete().eq("id", eventId);
      if (error) throw error;
      return json({ ok: true });
    }

    return json({ error: "Method not allowed" }, 405);
  } catch (err) {
    if (err instanceof AuthError) return json({ error: err.message }, 401);
    if (err instanceof BadRequest) return json({ error: err.message }, 400);
    console.error(err);
    // Don't hand internal error text to the browser.
    return json({ error: "Something went wrong saving that." }, 500);
  }
});
