# Vercel preview-build policy (AEGIS AI)

The Vercel project `aegis-ai` serves the Next.js frontend in `apps/web`. Backend-only commits to the monorepo do not normally need a frontend preview deployment. Excessive preview builds can consume the Hobby team's Functions Storage allowance.

## Current project-level Ignored Build Step

Configured in Vercel project settings on 2026-11-09:

```sh
if [ "$VERCEL_ENV" = production ]; then exit 1; fi; git diff --quiet HEAD^ HEAD -- ":(top)apps/web" ":(top)packages" ":(top)package.json" ":(top)pnpm-lock.yaml" ":(top)pnpm-workspace.yaml" ":(top)turbo.json"
```

Vercel's Ignored Build Step convention: exit code 0 skips a build; exit code 1 proceeds. The production guard deliberately allows production builds. A preview build is requested when the latest commit changes the frontend or shared dependency paths above. A backend-only or documentation-only commit should return zero and skip the preview build.

**Limitations:** The command assumes a usable Git parent commit in the Vercel build environment. If Git history is unavailable or the comparison errors, the nonzero result fails open and allows the build. A single-commit diff can miss earlier frontend changes when several commits are pushed together; verify behavior before relying on it as the only gate. Changes outside the listed paths that affect frontend output require revisiting this allowlist.

## Verification and rollback

1. Push a documentation-only change to a development branch and check whether Vercel marks its deployment skipped.
2. Push a frontend change and confirm a preview builds successfully.
3. Check production deployment behavior separately before changing release workflows.
4. If either check fails, remove the Ignored Build Step in Vercel project settings and investigate.

Do not delete production deployments. Any cleanup of old previews should be separately reviewed and approved. This policy does not change GitHub Actions or backend deployment behavior.
