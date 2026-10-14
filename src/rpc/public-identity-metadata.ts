import type { JsonValue } from './contracts';

/** Sanitize browser DTO metadata only; stored metadata and signed claims stay authoritative. */
export function normalizeMetadata(value: Record<string, unknown> | undefined): Readonly<Record<string, JsonValue>> | undefined {
    if (!value) return undefined;
    const normalized = JSON.parse(JSON.stringify(value)) as unknown;
    if (typeof normalized !== 'object' || normalized === null || Array.isArray(normalized)) {
        throw new Error('Invalid identity metadata');
    }
    const forbiddenKey = /access.?token|refresh.?token|jwt|authorization|cookie|password|invitationToken|verificationToken|resetToken|credential|secret/iu;
    const sanitize = (entry: JsonValue): JsonValue => {
        if (Array.isArray(entry)) return entry.map(sanitize);
        if (entry !== null && typeof entry === 'object') {
            return Object.fromEntries(Object.entries(entry)
                .filter(([key]) => !forbiddenKey.test(key))
                .map(([key, child]) => [key, sanitize(child)]));
        }
        return entry;
    };
    const source = normalized as Record<string, JsonValue>;
    const metadata = sanitize(source) as Record<string, JsonValue>;
    delete metadata.first_login_setup_required;
    if (typeof source.must_change_password === 'boolean') {
        metadata.first_login_setup_required = source.must_change_password;
    }
    return metadata;
}
