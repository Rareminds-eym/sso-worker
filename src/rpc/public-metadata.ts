import type { JsonValue } from "./contracts";

const FORBIDDEN_PUBLIC_METADATA_KEY = /access.?token|refresh.?token|jwt|authorization|cookie|password|invitationToken|verificationToken|resetToken|credential|secret/iu;

export function normalizePublicMetadata(value: Record<string, unknown> | null | undefined): Readonly<Record<string, JsonValue>> | undefined {
    if (!value) return undefined;
    const normalized = JSON.parse(JSON.stringify(value)) as unknown;
    if (!isRecord(normalized)) throw new Error("Invalid identity metadata");
    return stripForbiddenKeys(normalized) as Record<string, JsonValue>;
}

function stripForbiddenKeys(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(stripForbiddenKeys);
    if (!isRecord(value)) return value;

    return Object.fromEntries(
        Object.entries(value)
            .filter(([key]) => !FORBIDDEN_PUBLIC_METADATA_KEY.test(key))
            .map(([key, entry]) => [key, stripForbiddenKeys(entry)]),
    );
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
