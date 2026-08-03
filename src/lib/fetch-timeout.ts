/**
 * Fetch with timeout to prevent indefinite hanging
 * @param url URL to fetch
 * @param options Fetch options
 * @param timeoutMs Timeout in milliseconds (default: 5000)
 * @returns Response
 * @throws Error if timeout occurs or fetch fails
 */
export async function fetchWithTimeout(
	url: string,
	options: RequestInit = {},
	timeoutMs = 5000,
): Promise<Response> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const response = await fetch(url, {
			...options,
			signal: controller.signal,
		});
		clearTimeout(timeoutId);
		return response;
	} catch (error) {
		clearTimeout(timeoutId);
		if (error instanceof Error && error.name === "AbortError") {
			throw new Error(`Request timeout after ${timeoutMs}ms: ${url}`);
		}
		throw error;
	}
}
