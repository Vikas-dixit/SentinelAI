import { env } from 'cloudflare:workers';
import { createAnalystBrief, validateBriefRequest } from '../../../lib/llm-client.mjs';

export const runtime = 'edge';
const json = (body: unknown, status = 200) => Response.json(body, {status,headers:{'Cache-Control':'no-store'}});
const key = () => (env as unknown as {OPENAI_API_KEY?:string}).OPENAI_API_KEY;

export async function GET() {
  return json({configured: Boolean(key()), provider:'OpenAI', model:'gpt-5.6-luna'});
}

export async function POST(request: Request) {
  // The Site is owner-private; additionally require its authenticated dispatch identity.
  if (!request.headers.get('oai-authenticated-user-id')) return json({error:'Sign in to review evidence.'},401);
  if (!key()) return json({error:'External AI is not configured for this site.'},503);
  if (Number(request.headers.get('content-length')||0)>30_000) return json({error:'Request too large.'},413);
  let context;
  try { context=validateBriefRequest(await request.json()); }
  catch (error) { return json({error:error instanceof Error?error.message:'Invalid request.'},400); }
  try {
    const brief=await createAnalystBrief(context,key()!);
    return json({brief});
  } catch(error) {
    return json({error:error instanceof Error?error.message:'AI review unavailable.'},502);
  }
}
