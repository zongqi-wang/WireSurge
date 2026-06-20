# Agent Prompt: Create and Dry Run a Request

Use WireSurge as a non-interactive CLI.

1. Inspect the request schema:

   ```sh
   wiresurge schema request
   ```

2. Initialize a workspace if needed:

   ```sh
   wiresurge workspace init --output json
   ```

3. Create a request with JSON:

   ```sh
   wiresurge request create --json '{"id":"req-health","name":"Health","url":"http://127.0.0.1:8080/health"}' --output json
   ```

4. Dry run before sending traffic:

   ```sh
   wiresurge run req-health --dry-run --output json
   ```

