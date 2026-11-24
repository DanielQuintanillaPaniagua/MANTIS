# External Validation Specs

To validate MANTIS against real vulnerable labs, you need their OpenAPI specs.
Place the downloaded files in this directory (`examples/openapi/`) before running `scripts/validate_external.ps1`.

> **Note (Windows / PowerShell):** use `curl.exe` instead of `curl`. In PowerShell, `curl` is an alias of `Invoke-WebRequest`, and redirecting with `>` can save the file as UTF-16, which breaks JSON parsing.

## VAmPI

1. Run VAmPI:

   ```bash
   docker run -p 5000:5000 erev0s/vampi
   ```

2. Initialize the database (required the first time):

   ```bash
   curl.exe http://localhost:5000/createdb
   ```

3. Download the spec:

   ```bash
   curl.exe -o vampi.json http://localhost:5000/openapi.json
   ```

   If that endpoint does not return the spec in your version, download it from the project repository: <https://github.com/erev0s/VAmPI> (look for `openapi_specs/`).

## crAPI

1. Run crAPI (see <https://github.com/OWASP/crAPI> for the official instructions):

   ```bash
   docker-compose up
   ```

2. Download the spec from the repository (the running web app on port 8888 does not necessarily serve it):

   ```bash
   curl.exe -o crapi.json https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json
   ```

   Adjust the path if the repository layout has changed.

## Next step

With the specs in place, run:

```powershell
./scripts/validate_external.ps1 -Target vampi
# or
./scripts/validate_external.ps1 -Target crapi
```

Results are saved in `docs/validation/results/`.