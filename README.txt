While attempting to use Google Security Team's CVE-2017-14491 in dnsmasq versions <2.78, I found a new exploit present
in dnsmasq <2.76. In this case, an attacker controlled dns server to could send a response greater than 4096 bytes. 
Since this response is truncated at 4096 bytes, part of the packet is left off, a "tail." When examing the source code,
I found that dnsmasq in do_doctor() in rfc1035.c iterates through each answer record. In this function, the pointer to
the packet read is incremented by 4 bytes to bypass the time to live section of the answer. Since a large packet is 
truncated at 4096 bytes, this pointer can read further beyond the memory allocated to it on the heap, potentially 
causing a bad read leading to a crash and denial of service. 

The proof-of-concept (poc) provided are heavily based off of the research done by Google's security team in 2017.
Copyright 2017 Google Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Authors:
  Fermin J. Serna <fjserna@google.com>
  Felix Wilhelm <fwilhelm@google.com>
  Gabriel Campana <gbrl@google.com>
  Kevin Hamacher <hamacher@google.com>
  Gynvael Coldwind <gynvael@google.com>
  Ron Bowes - Xoogler :/ 

See their blogpost here: https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html
See their github here: https://github.com/google/security-research-pocs/tree/master/vulnerabilities/dnsmasq

For more information on dnsmasq see: https://github.com/imp/dnsmasq
Dnsmasq is a project from Simon Kelley, and can be seen here: http://thekelleys.org.uk/dnsmasq/doc.html

The git commit affected is this one and before: 15379ea1f252d1f53c5d93ae970b22dedb233642 
