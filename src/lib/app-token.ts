import type { AccessTokenPayload, Env } from "../types";
import { signAccessToken } from "./jwt";

export async function signLteAccessToken(
  payload: AccessTokenPayload,
  env: Env,
): Promise<string> {
  return signAccessToken(
    {
      ...payload,
      products: payload.products.includes("lte") ? payload.products : [...payload.products, "lte"],
    },
    env,
  );
}
