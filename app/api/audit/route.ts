import { NextResponse } from "next/server"
import { z } from "zod"

import { runAudit } from "@/lib/audit-engine"
import {
  DEFAULT_AUDITOR_MODEL,
  DEFAULT_TARGET_MODEL,
  TEST_PROFILE_KEYS,
  defaultProfiles,
} from "@/lib/audit-types"

export const runtime = "nodejs"

const profileSchema = z.object(
  Object.fromEntries(TEST_PROFILE_KEYS.map((key) => [key, z.boolean()])) as {
    [K in (typeof TEST_PROFILE_KEYS)[number]]: z.ZodBoolean
  }
)

const requestSchema = z.object({
  endpoint: z.string().trim().min(1),
  relayApiKey: z.string().trim().min(1),
  targetModel: z.string().trim().min(1).default(DEFAULT_TARGET_MODEL),
  auditorModel: z.string().trim().min(1).default(DEFAULT_AUDITOR_MODEL),
  includeBaseline: z.boolean().default(false),
  captureFullResponses: z.boolean().default(false),
  profiles: profileSchema.default(defaultProfiles),
  customInstruction: z.string().max(1200).optional(),
})

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const payload = requestSchema.parse(body)
    const report = await runAudit(payload)

    return NextResponse.json(report)
  } catch (error) {
    const message =
      error instanceof z.ZodError
        ? error.issues.map((issue) => issue.message).join("; ")
        : error instanceof Error
          ? error.message
          : "Unknown audit error"

    return NextResponse.json({ error: message }, { status: 400 })
  }
}

