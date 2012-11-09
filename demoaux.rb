require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    def initialize
        super(
            'Name'			=>	'Auxiliary module example.',
            'Version'		=>	'$Revision: 0 $',
            'Description'	=>	'Our first Measploit Module.',
            'Author'		=>
			[
				'Roi Mallo',
				'Jesus Perez <jesusprubio[at]gmail.com>'
			],
			'License' => MSF_LICENSE
        )

        register_options(
        [
            OptString.new('GREETING', [ true, "Words to say.", "Hi world! ;)" ])
        ], self.class)
    end

    def run()
        puts datastore['GREETING']
    end

end
