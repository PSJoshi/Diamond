#!/usr/bin/env python

# coding=utf-8
"""
Shells out to read php.ini settings to determine PHP security

References - 
http://codebase.eu/source/code-php/security-test/
http://www.cyberciti.biz/tips/php-security-best-practices-tutorial.html

"""

import diamond.collector
import subprocess
import os
import re

php_security_parameters = [
{'expose_php':'off'},
{'display_errors':'off'},
{'log_errors':'on'},
{'allow_url_fopen':'off'},
{'allow_url_include':'off'},
{'disable_functions':['exec','passthru','shell_exec','system','proc_open','popen','curl_exec','curl_multi_exec','parse_ini_file','show_source']},
{'max_input_time':'30'},
{'max_execution_time':'30'},
{'memory_limit':'40M'},
{'open_basedir':'/var/www/html'},
{'file_uploads':'off'},
{'upload_max_filesize':'1M'},
{'magic_quotes_gpc':'off'},
{'post_max_size':'1K'},
{'register_globals':'off'},
{'track_errors':'yes'},
{'safe_mode':'on'},
{'session_cookie_httponly':'1'},
{'session_cookie_secure':'1'},
# {'session.save_path':''},
# {'session.referer_check':''},

]
class PHPHardeningCollector(diamond.collector.Collector):
	def get_default_config_help(self):
		config_help = super(PHPHardeningCollector,self).get_default_config_help()
		config_help.update({
			'use_sudo':'Use sudo?',
			'sudo_cmd':'Path to do sudo',
			'php_ini_path':'/etc/php.ini'
		})
		return config_help

	def get_default_config(self):
		config = super(PHPHardeningCollector,self).get_default_config()
		config.update({
			'use_sudo':False,
			'sudo_cmd':'/usr/bin/sudo',
			'php_ini_path':'/etc/php.ini',
			'enabled':True,
		})

		return config
	
	def collect(self):
		if not os.path.isfile(self.config['php_ini_path']):
			self.log.error("PHP Ini configuration file - %s is not found",self.config['php_ini_path'])
			return False
		command = 'cat ' + self.config['php_ini_path'] + '|' + "grep -v ^';'" + '|' + 'grep -v ^$'
		self.log.info("PHPHardening Collector - command being executed -%s ",command)	
		cmd_results = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
		# convert to list
		result_list = cmd_results.split('\n')
		self.log.info("Command results -%s",result_list)
		for security_parameter in php_security_parameters:
			for dict_key,dict_value in security_parameter.items():
				check_result = filter(lambda x:dict_key in x, result_list)
				result_value=None
				if '=' in check_result:
					result_value = check_result[0].split('=')[1].strip().lower()
					self.log.info("check_result-%s",check_result)
					self.log.info("result_value-%s",result_value)
				else:
					# PHP security parameter not present
					self.publish(dict_key,0)
				
				#publish value as boolean if there is a match
				if result_value:
					if dict_key == 'expose_php':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					 
					if dict_key == 'display_errors':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'log_errors':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'allow_url_fopen':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'allow_url_include':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'max_input_time':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'max_execution_time':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'memory_limit':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'file_uploads':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'upload_max_filesize':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'magic_quotes_gpc':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'post_max_size':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'register_globals':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'track_errors':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
					if dict_key == 'safe_mode':
						if dict_value.strip()== result_value:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)

					if dict_key == 'disable_functions':
						self.log.info("Disable functions - %s",result_value)
						if len(set(dict_value).intersection(result_value))>0:
							self.publish(dict_key,1)
						else:
							self.publish(dict_key,0)
					
