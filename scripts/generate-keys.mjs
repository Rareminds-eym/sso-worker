/**
 * Generate RS256 key pair for JWT signing.
 *
 * Usage:
 *   node scripts/generate-keys.mjs
 *
 * Then set the secrets:
 *   wrangler secret put JWT_PRIVATE_KEY < private.pem
 *   wrangler secret put JWT_PUBLIC_KEY  < public.pem
 *   wrangler secret put JWT_KID
 */
import { generateKeyPair, exportPKCS8, exportSPKI } from "jose";
import { writeFileSync } from "node:fs";

const { privateKey, publicKey } = await generateKeyPair("RS256");

const privatePem = await exportPKCS8(privateKey);
const publicPem = await exportSPKI(publicKey);

writeFileSync("private.pem", privatePem);
writeFileSync("public.pem", publicPem);

console.log("✅ Keys generated:");
console.log("   private.pem (keep secret!)");
console.log("   public.pem  (safe to share)");
console.log("");
console.log("Set secrets:");
console.log("   cat private.pem | wrangler secret put JWT_PRIVATE_KEY");
console.log("   cat public.pem  | wrangler secret put JWT_PUBLIC_KEY");
console.log('   echo "key-1"    | wrangler secret put JWT_KID');
