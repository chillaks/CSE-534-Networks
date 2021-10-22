import sys
import time
import socket
from datetime import datetime as dt
import dns.rdatatype, dns.opcode, dns.rcode, dns.flags
from dns import message as dns_message, query as dns_query, name as dns_name

# List of 13 geographically distributed Root DNS Servers fetched from https://www.iana.org/domains/root/servers
root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',
'192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17',
'192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

# Timeout if iterative query to name server does not resolve within 10 seconds
QUERY_TIMEOUT = 10

# Iterative Query: Single query to a DNS Server (Root/TLD/Name/Authoritative) to get the IP address of the DNS server in the immediate
# next hierarchy, until we eventually resolve the query domain IP address. We make a series of iterative queries to different DNS servers
# from the machine that runs this code, as opposed to the traditional implementation where the resolution task is handed over to a local 
# DNS server that uses recursive queries instead.
def iterative_resolve(domain_name, rd_type, name_server, time_out = QUERY_TIMEOUT):
    domain_name = dns_name.from_text(domain_name)
    query = dns_message.make_query(qname = domain_name, rdtype = rd_type)
    try:
        dns_response = dns_query.udp(q = query, where = name_server, timeout = time_out)
        return dns_response
    except Exception as e:
        raise e

# Core resolution logic of custom dig implementation
def mydig_resolver(domain_name, rd_type, resolve_cname = False, return_A_record = False, recursive = False):
    dns_response = None
    
    for root_server in root_servers:
        try:
            root_dns_response = iterative_resolve(domain_name, rd_type, name_server = root_server)
            dns_response = root_dns_response
        except Exception as e:
            print("Error when fetching from Root Server {}. Error: {}".format(root_server, e))
            continue
        
        while(not dns_response.answer):
            # First read from Additional section which contains all the IPs of the next name servers which can be queried in the hierarchy
            if len(dns_response.additional) > 0:
                for rrset in dns_response.additional:
                    # Consider only IPv4 addresses (Ignoring IPv6 which have 'AAAA' type)
                    if rrset[0].rdtype == dns.rdatatype.A:
                        next_ns_ip_addr = rrset[0].address
                        try:
                            # Query the TLD / next set of name servers in the hierarchy until we get an Answer section containing final IP
                            ns_dns_response = iterative_resolve(domain_name, rd_type, name_server = next_ns_ip_addr)
                            if resolve_cname and ns_dns_response.answer and ns_dns_response.answer[0].rdtype == dns.rdatatype.CNAME:
                                return ns_dns_response
                            elif return_A_record and ns_dns_response.answer and ns_dns_response.answer[0].rdtype == dns.rdatatype.A:
                                return ns_dns_response
                            dns_response = ns_dns_response
                            break
                        except Exception as e:
                            print("Error when fetching from Name Server {} with IP {}. Error: {}".format(
                                rrset.name.to_text(), next_ns_ip_addr, e))
            
            # When the Additional section is empty, verify and resolve the domain name of the authoritative name servers which 
            # will be stored in the Authority section
            elif len(dns_response.authority) > 0:
                for rrset in dns_response.authority:
                    # Return when we encounter an SOA RRSet
                    if rrset.rdtype == dns.rdatatype.SOA:
                        return dns_response
                    
                    # Additional hop here to resolve the IP address of the authoritative name server from its domain name
                    ns_domain_name = rrset[0].target.to_text()
                    ns_dns_response = mydig_resolver(ns_domain_name, 'A', return_A_record = True)
                    # If we are not resolving the CName, then query the IP address obtained
                    if not resolve_cname:
                        for auth_rrset in ns_dns_response.answer:
                            auth_ip_addr = auth_rrset[0].address
                            try:
                                # Finally, get the IP of the query domain from the authoritative name server
                                auth_dns_response = iterative_resolve(domain_name, rd_type, name_server = auth_ip_addr)
                                dns_response = auth_dns_response
                            except Exception as e:
                                print("Error when fetching from Authoritative Server {} with IP {}. Error: {}".format(
                                    auth_ip_addr, auth_rrset.name.to_text(), e))
                    else:
                        return ns_dns_response
            else:
                # Either Answer or Authority is always included in the response, almost impossible to reach this block.
                print("GG rekt")
        
        for rrset in dns_response.answer:
            # If A or SOA records found in Answer, return them to denote successful resolution
            if dns.rdatatype.from_text(rd_type).value == dns.rdatatype.A and (rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.SOA):
                return dns_response

        for rrset in dns_response.answer:
            # If the Answer section contains only a CNAME type RRSET, resolve it further until we get A records(s) 
            # corresponding to the CNAME address
            while rrset.rdtype == dns.rdatatype.CNAME:
                cname_domain_name = rrset[0].target.to_text()
                cname_dns_response = mydig_resolver(cname_domain_name, 'A', resolve_cname = True)
                for cname_rrset in cname_dns_response.answer:
                    if cname_rrset.rdtype == dns.rdatatype.CNAME:
                        dns_response.answer.append(cname_rrset)
                        break
                    else:
                        authoritative_ip = cname_rrset[0].address
                        try:
                            # Try to resolve the IP address of the CName
                            auth_dns_response = iterative_resolve(cname_domain_name, rd_type, name_server = authoritative_ip)
                            if not auth_dns_response.answer and auth_dns_response.authority: 
                                if dns.rdatatype.from_text(rd_type).value != dns.rdatatype.A:
                                    dns_response.authority.extend(auth_dns_response.authority)
                                else:
                                    # Additional hop here when the CName maps to the name of another authoritative name server
                                    for auth_rrset in auth_dns_response.authority:
                                        auth_domain_name = auth_rrset.name.to_text()
                                        auth_dns_response = mydig_resolver(auth_domain_name, 'A', resolve_cname = True)
                                        if auth_dns_response.answer:
                                            break
                            for auth_rrset in auth_dns_response.answer:
                                dns_response.answer.append(auth_rrset)
                            break
                        except Exception as e:
                            print("Error when fetching from Authoritative Server {} with IP {}. Error: {}".format(
                                    cname_rrset.name.to_text(), authoritative_ip, type(e)))
                break
        break
 
    return dns_response

def dig_output(domain_name, dns_response, tt):
    num_queries = len(dns_response.question)
    num_additional= len(dns_response.additional) + 1
    num_authority = len(dns_response.authority)
    num_answers = 0
    for rrset in dns_response.answer:
        num_answers += len(rrset.items)
    
    flags = dns.flags.to_text(dns_response.flags)
    opcode_str = dns.opcode.to_text(dns_response.opcode())
    status = dns.rcode.to_text(dns_response.rcode())
    hostname = socket.gethostname()

    op_str = ("\n; <<>> myDig 1.0.0 <<>> {}\n"
    ";; global options: +cmd\n;; Got answer:\n"
    ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n"
    ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n"
    ";; OPT PSEUDOSECTION:\n"
    ";; EDNS: version: 0, flags:; udp: 512\n").format(domain_name, opcode_str, status, dns_response.id, flags, num_queries, 
        num_answers, num_authority, num_additional)
    
    op_str += ';; QUESTION SECTION:\n; ' + '\n'.join([rrset.to_text() for rrset in dns_response.question]) + '\n\n'
    if num_answers > 0:
        op_str += ';; ANSWER SECTION:\n' + '\n'.join([rrset.to_text() for rrset in dns_response.answer]) + '\n\n'
    if num_authority > 0:
        op_str += ';; AUTHORITY SECTION:\n' + '\n'.join([rrset.to_text() for rrset in dns_response.authority]) + '\n\n'
    
    op_str += ";; Query time: {} msec\n".format(str(int(tt * 1000)))
    op_str += ";; SERVER: {}\n".format(hostname)
    op_str += ";; WHEN: {}\n".format(dt.now().strftime("%a %b %d %H:%M:%S EDT %Y"))
    op_str += ";; MSG SIZE  rcvd: {}\n".format(sys.getsizeof(dns_response.to_text()))
    
    return op_str


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Please enter 2 arguments, where the first is the domain name to resolve, and second is the RR type (can be one of A, NS or MX)")
        exit(0)
    
    #domain_name = 'netflix.com'
    #rdtype = 'A'
    domain_name = sys.argv[1]
    rdtype = sys.argv[2]
    if rdtype not in ['A', 'NS', 'MX']:
        print("Please ensure the RR type is one of A, NS or MX")
    
    start = time.time()
    dns_response = mydig_resolver(domain_name, rdtype)
    tt = time.time() - start

    print(dig_output(domain_name, dns_response, tt))
