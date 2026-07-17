@echo off
REM Gives the Planner's push-notification Worker a Firebase service-account
REM credential, then deploys it.
REM
REM WHY: the Worker currently reads AND writes your planner doc in Firestore
REM with no authentication. That only works because the rules are wide open —
REM the same hole that lets anyone read your client names and invoice amounts.
REM Once the rules lock, an unauthenticated Worker gets 403 and your reminders
REM would die silently. This gives it a proper credential so the lock is safe.
REM
REM Claude can't run this: piping a private key into wrangler trips its
REM credential-handling guardrail. The key it reads was generated for your
REM own project and lives only in WORK\config\ (gitignored, never in a repo).
REM
REM SAFE TO RUN NOW: the Worker falls back to anonymous if the secret is
REM missing, so this changes nothing until the rules actually lock.

cd /d "%~dp0"
echo.
echo   [1/2] Uploading the service-account key as a Worker secret...
type "C:\Users\kandy\WORK\config\firebase-wellness-sa.json" | npx wrangler secret put FIREBASE_SA_JSON --config wrangler.toml
if %errorlevel% neq 0 goto :failed

echo.
echo   [2/2] Deploying the Worker...
npx wrangler deploy --config wrangler.toml
if %errorlevel% neq 0 goto :failed

echo.
echo   DONE. The Worker can now talk to Firestore even once the rules lock.
echo   Tell Claude it's deployed and it will lock the planner's data.
goto :end

:failed
echo.
echo   FAILED - see the message above. Nothing was locked, so your planner
echo   and reminders are unaffected.

:end
echo.
pause
