import type { Env } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";

export async function listPlans(
  _req: Request,
  env: Env,
): Promise<Response> {
  const database = db(env);
  const plans = await database.query(
    "plans?is_active=eq.true&order=display_order.asc",
  );
  return json(plans);
}

export async function getPlanByCode(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const code = url.pathname.split("/").pop();
  if (!code) return error("Plan code required", 400);

  const database = db(env);
  const plan = await database.queryOne(
    `plans?plan_code=eq.${encodeURIComponent(code)}&is_active=eq.true`,
  );
  if (!plan) return error("Plan not found", 404);
  return json(plan);
}


