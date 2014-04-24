#!/usr/bin/env python

# coding=utf-8

"""
This collector checks existing sysctl values from network security and performance point of view and raises alarms if the values are not ok.
References for desired syctl settings:
http://klaver.it/linux/sysctl.conf
http://www.dsm.fordham.edu/~mathai/kernel.html
http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf
 
Shells out to get the values of sysctl settings

#### Dependencies

 * /sbin/sysctl

"""

import diamond.collector
import subprocess
import os
import re
from diamond.collector import str_to_bool

_RE = re.compile(r'^([a-z\._]*) = ([0-9]*)$')

kernel_security_and_performance_parameters = [

    # general system security options
    {'kernel.exec-shield':'1'},
    {'kernel.randomize_va_space':['1','2']},
    {'kernel.sysrq':'0'},
    {'kernel.panic':'0'},
    {'kernel.panic_on_oops':'0'},

    # network security options

    # prevent SYN attacks, enable SYN cookies
    {'net.ipv4.tcp_syncookies':'1'},
    {'net.ipv4.tcp_syn_retries':'5'},
    {'net.ipv4.tcp_synack_retries':'2'},
    {'net.ipv4.tcp_max_syn_backlog':'4096'},
    # disable packet_forwarding
    {'net.ipv4.ip_forward':'0'},
    {'net.ipv4.conf.all.forwarding':'0'},
    {'net.ipv4.conf.default.forwarding':'0'},
    # ip spoofing protection, source_route verification
    {'net.ipv4.conf.all.rp_filter':'1'},
    {'net.ipv4.conf.default.rp_filter':'1'},
    # disable ICMP redirect acceptance
    {'net.ipv4.conf.all.accept_redirects':'0'},
    {'net.ipv4.conf.default.accept_redirects':'0'},
    # disable log spoofed packets, source routed packets and redirect packets
    {'net.ipv4.conf.all.log_martians':'1'},
    {'net.ipv4.conf.default.log_martians':'1'},
    {'net.ipv4.conf.all.accept_source_route':'0'},
    {'net.ipv4.conf.default.accept_source_route':'0'},
    # decrease time default value for tcp_fin_timeout connection
    {'net.ipv4.tcp_fin_timeout':'15'},
    # decrease time default value for connections to be alive
    {'net.ipv4.tcp_keepalive_time':'300'},
    {'net.ipv4.tcp_keepalive_probes':'5'},
    {'net.ipv4.tcp_keepalive_intvl':'15'},
    # don't relay bootp
    {'net.ipv4.conf.all.bootp_relay':'0'},
    # don't proxy arp for anyone
    {'net.ipv4.conf.all.proxy_arp':'0'},
    # ignore ICMP broadcasts
    {'net.ipv4.icmp_echo_ignore_broadcasts':'1'},
    # ignore ICMP echo
    {'net.ipv4.icmp_echo_ignore_all':'1'},
    # Ignore send redirects
    {'net.ipv4.conf.all.send_redirects':'0'},
    {'net.ipv4.conf.default.send_redirects':'0'},
    # Accept ICMP redirects from default gateway only
    {'net.ipv4.conf.all.secure_redirects':'1'},
    # Enable bad error message Protection
    {'net.ipv4.icmp_ignore_bogus_error_responses':'1'},
    # Turn on the tcp_timestamps
    {'net.ipv4.tcp_timestamps':'1'},
    # Turn on SACK
    {'net.ipv4.tcp_dsack':'1'},
    {'net.ipv4.tcp_sack':'1'},
    {'net.ipv4.tcp_fsack':'1'},
    # Enable a fix for RFC1337 - time-wait assassination hazards in TCP
    {'net.ipv4.tcp_rfc1337':'1'},
    # Allowed local port range
    {'net.ipv4.ip_local_port_range':'16384 65536'},

    # system memory management options
    # Do less swapping
    {'vm.swappiness':'10'},
    {'vm.dirty_ratio':'60'},
    {'vm.dirty_background_ratio':'2'},
    # No overcommitment of available memory
    {'vm.overcommit_ratio ':'0'},
    {'vm.overcommit_memory':'0'},

    # Network performance tunning

    # Do a 'modprobe tcp_cubic' first
    {'net.ipv4.tcp_congestion_control':'cubic'},

    # Turn on the tcp_window_scaling
    {'net.ipv4.tcp_window_scaling':'1'},

    # Increase the maximum total buffer-space allocatable
    # This is measured in units of pages (4096 bytes)
    {'net.ipv4.tcp_mem':'65536 131072 262144'},
    {'net.ipv4.udp_mem':'65536 131072 262144'},

    # Increase the read-buffer space allocatable
    {'net.ipv4.tcp_rmem':'8192 87380 16777216'},
    {'net.ipv4.udp_rmem_min':'16384'},
    {'net.core.rmem_default':'131072'},
    {'net.core.rmem_max':'16777216'},

    # Increase the write-buffer-space allocatable
    {'net.ipv4.tcp_wmem':'8192 65536 16777216'},
    {'net.ipv4.udp_wmem_min':'16384'},
    {'net.core.wmem_default':'131072'},
    {'net.core.wmem_max':'16777216'},

    # Increase number of incoming connections
    {'net.core.somaxconn':'32768'},
    # Increase number of incoming connections backlog
    {'net.core.netdev_max_backlog':'4096'},
    {'net.core.dev_weight': '64'},
    # Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
    {'net.ipv4.tcp_max_tw_buckets': '1440000'},
    {'net.ipv4.tcp_tw_recycle':'1'},
    {'net.ipv4.tcp_tw_reuse': '1'},

    # Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
    {'net.ipv4.tcp_max_orphans': '16384'},
    {'net.ipv4.tcp_orphan_retries':'0'},

    # Increase the maximum memory used to reassemble IP fragments
    {'net.ipv4.ipfrag_high_thresh': '512000'},
    {'net.ipv4.ipfrag_low_thresh': '446464'},
  ]


class SysHardeningCollector(diamond.collector.Collector):

    def get_default_config_help(self):
        config_help = super(SysHardeningCollector, self).get_default_config_help()
        config_help.update({
            'use_sudo': 'Use sudo?',
            'sudo_cmd': 'Path to sudo',
            'bin': 'Path to sysctl library'
        })
        return config_help

    def get_default_config(self):
        """
        Returns the default collector settings
        """
        config = super(SysHardeningCollector, self).get_default_config()
        config.update({
            'path': 'sysharden',
            'use_sudo': False,
            'sudo_cmd': '/usr/bin/sudo',
            'bin': '/sbin/sysctl',
        })
        return config

    def collect(self):

        if not os.access(self.config['bin'], os.X_OK):
            self.log.error("%s is not executable",self.config['bin'])
            return False

        command = [self.config['bin'], '-a']

        if str_to_bool(self.config['use_sudo']):
            command.insert(0,self.config['sudo_cmd'])

        cmd_results = subprocess.Popen(command,stdout=subprocess.PIPE).communicate()[0]
        # convert to list
        results_list = cmd_results.split('\n')

        for kernel_parameter in kernel_security_and_performance_parameters:
            for dict_key,dict_value in kernel_parameter.items():
                check_result = filter(lambda x:dict_key in x,results_list)
                if check_result:
                    result_value = check_result[0].split('=')[1].strip()

                # publish the value as boolean/integer depending on kernel metric to be monitored.
                if check_result and result_value:

                    # kernel ExecShield protection
                    if dict_key == 'kernel.exec-shield':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # randomize address space
                    if dict_key == 'kernel.randomize_va_space':
                        if result_value in dict_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Disable kernel sysrq key that passes commands directly to kernel
                    if dict_key == 'kernel.sysrq':
                        if result_value==dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # auto-reboot linux kernel panic
                    # kernel panic settings
                    if dict_key == 'kernel.panic':
                        if result_value == dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # kernel panic settings
                    if dict_key == 'kernel.panic_on_oops':
                        if result_value == dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # tcp syncookies
                    if dict_key == 'net.ipv4.tcp_syncookies':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # tcp syn retries
                    if dict_key == 'net.ipv4.tcp_syn_retries':
                        if result_value >=3 :#dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # tcp syn-ack retries
                    if dict_key == 'net.ipv4.tcp_synack_retries':
                        if result_value >=3 :#dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # tcp max. syn backlog
                    if dict_key == 'net.ipv4.tcp_max_syn_backlog':
                        if result_value >=4096 :#dict_value.strip():
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # ip forwarding
                    if dict_key == 'net.ipv4.ip_forward':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # ip all forwarding
                    if dict_key == 'net.ipv4.conf.all.forwarding':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)
                    # ip default forwarding
                    if dict_key == 'net.ipv4.conf.default.forwarding':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)
                    # ip spoofing protection, source_route verification
                    if dict_key == 'net.ipv4.conf.all.rp_filter':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.default.rp_filter':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # disable ICMP redirect acceptance
                    if dict_key == 'net.ipv4.conf.all.accept_redirects':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.default.accept_redirects':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # disable log spoofed packets, source routed packets and redirect packets
                    if dict_key == 'net.ipv4.conf.all.log_martians':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.default.log_martians':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.all.accept_source_route':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.default.accept_source_route':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # decrease time default value for tcp_fin_timeout connection
                    if dict_key == 'net.ipv4.tcp_fin_timeout':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # decrease time default value for connections to be alive
                    if dict_key == 'net.ipv4.tcp_keepalive_time':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_keepalive_probes':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_keepalive_intvl':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # don't relay bootp

                    if dict_key == 'net.ipv4.conf.all.bootp_relay':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # don't proxy arp for anyone
                    if dict_key == 'net.ipv4.conf.all.proxy_arp':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # ignore ICMP broadcasts
                    if dict_key == 'net.ipv4.icmp_echo_ignore_broadcasts':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # ignore ICMP echo
                    if dict_key == 'net.ipv4.icmp_echo_ignore_all':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Ignore send redirects
                    if dict_key == 'net.ipv4.conf.all.send_redirects':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.conf.default.send_redirects':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Accept ICMP redirects from default gateway only
                    if dict_key == 'net.ipv4.conf.all.secure_redirects':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Enable bad error message Protection
                    if dict_key == 'net.ipv4.icmp_ignore_bogus_error_responses':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Turn on the tcp_timestamps
                    if dict_key == 'net.ipv4.tcp_timestamps':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Turn on SACK
                    if dict_key == 'net.ipv4.tcp_dsack':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_sack':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_fsack':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Enable a fix for RFC1337 - time-wait assassination hazards in TCP
                    if dict_key == 'net.ipv4.tcp_rfc1337':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Allowed local port range
                    if dict_key == 'net.ipv4.ip_local_port_range':
                        result_value_list = [item for item in result_value.split(' ') if item !='']
                        dict_values_list = [item for item in result_value.split(' ') if item !='']
                        if dict_values_list == result_value_list:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Do less swapping
                    if dict_key == 'vm.swappiness':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'vm.dirty_ratio':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'vm.dirty_background_ratio':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # No overcommitment of available memory
                    if dict_key == 'vm.overcommit_ratio':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'vm.overcommit_memory':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Do a 'modprobe tcp_cubic' first
                    if dict_key == 'net.ipv4.tcp_congestion_control':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Turn on the tcp_window_scaling
                    if dict_key == 'net.ipv4.tcp_window_scaling':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase the maximum total buffer-space allocatable
                    # This is measured in units of pages (4096 bytes)
                    if dict_key == 'net.ipv4.tcp_mem':
                        result_value_list = [item for item in result_value.split(' ') if item !='']
                        dict_values_list = [item for item in result_value.split(' ') if item !='']
                        if dict_values_list == result_value_list:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.udp_mem':
                        result_value_list = [item for item in result_value.split(' ') if item !='']
                        dict_values_list = [item for item in result_value.split(' ') if item !='']
                        if dict_values_list == result_value_list:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase the read-buffer space allocatable
                    if dict_key == 'net.ipv4.tcp_rmem':
                        result_value_list = [item for item in result_value.split(' ') if item !='']
                        dict_values_list = [item for item in result_value.split(' ') if item !='']
                        if dict_values_list == result_value_list:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.udp_rmem_min':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.core.rmem_default':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.core.rmem_max':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase the write-buffer-space allocatable
                    if dict_key == 'net.ipv4.tcp_wmem':
                        result_value_list = [item for item in result_value.split(' ') if item !='']
                        dict_values_list = [item for item in result_value.split(' ') if item !='']
                        if dict_values_list == result_value_list:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.udp_wmem_min':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.core.wmem_default':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.core.wmem_max':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase number of incoming connections
                    if dict_key == 'net.core.somaxconn':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase number of incoming connections backlog
                    if dict_key == 'net.core.netdev_max_backlog':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.core.dev_weight':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
                    if dict_key == 'net.ipv4.tcp_max_tw_buckets':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_tw_recycle':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_tw_reuse':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
                    if dict_key == 'net.ipv4.tcp_max_orphans':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.tcp_orphan_retries':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    # Increase the maximum memory used to reassemble IP fragments
                    if dict_key == 'net.ipv4.ipfrag_high_thresh':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)

                    if dict_key == 'net.ipv4.ipfrag_low_thresh':
                        if dict_value.strip() == result_value:
                            self.publish(dict_key,1)
                        else:
                            self.publish(dict_key,0)






