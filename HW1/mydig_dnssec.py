import sys
import time
import socket
from datetime import datetime as dt
from dns import message as dns_message, query as dns_query, name as dns_name
import dns.rdatatype, dns.dnssec, dns.opcode, dns.rcode, dns.flags

# Some Acronyms used in this code and comments:
# 1. PubKSK: The public key part of a zone's Key Signing Key
# 2. PubZSK: The public Key part of a zone's Zone Signing Key
# 3. RRSet: Resource Record Set, a set of records with same type (rdtype) and zone
# 4. RRSig: Resource Record Signature, contains digital signature for the corresponding RRSet (which could be DNSKey/DS/A)
# 5. DS: Delegation of Signing, contains the digest/hash of a child zone's PubKSK

# List of 13 geographically distributed Root DNS Servers fetched from https://www.iana.org/domains/root/servers
root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',
'192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17',
'192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

# Timeout if iterative query to name server does not resolve within 10 seconds
QUERY_TIMEOUT = 10

# Follow README at https://github.com/iana-org/get-trust-anchor to generate current active root trust anchor
root_anchor_active = '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D'.lower()
hash_algorithms = {1: 'SHA1', 2: 'SHA256'}

# Return the record having RRSig rdatatype from either the Answer or Authority Section of the DNSSec response, depending on whether 
# or not it was returned by the Authoritative Name Server.
def get_rrsig(section):
	return next((rrset for rrset in section if rrset.rdtype == dns.rdatatype.RRSIG), None)

# return the DNSKey RRSet and the RR having a value of 257, which indicates that it contains the PubKSK
def get_dnskey_rrset_and_ksk(answer):
    for rrset in answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            return next(((rrset, rr) for rr in rrset if rr.flags == 257), (None, None))
    return None, None

# Fetch A RRSet from Answer section of DNSSec response of Authoritative NS
def get_rrset_a(answer):
    return next((rrset for rrset in answer if rrset.rdtype == dns.rdatatype.A), None)

# Fetch DS RRSet from Answer section of DNSSec response of non-Authoritative NS
def get_rrset_ds(authority):
    return next((rrset for rrset in authority if rrset.rdtype == dns.rdatatype.DS), None)

def is_zone_verified(parent_ds_rrset, ksk):
    hash_algo = 'SHA256' if parent_ds_rrset is None else hash_algorithms.get(parent_ds_rrset[0].digest_type, 2)
    parent_ds_hash = root_anchor_active if parent_ds_rrset is None else parent_ds_rrset[0].to_text()
    zone = '.' if parent_ds_rrset is None else parent_ds_rrset.name.to_text()
    try:
        hash = dns.dnssec.make_ds(name = zone, key = ksk, algorithm = hash_algo).to_text()
    except dns.dnssec.ValidationFailure as e:
        print("Hash Algorithm {} not supported: {}".format(hash_algo, e))
        return False
    else:
        if hash == parent_ds_hash:
            if zone == '.':
                print("The PubKSK digest matches the root anchor key digest. Hence, Root Zone '{}' successfully verified".format(zone))
            else:
                print("The PubKSK digest matches the DS record from the parent zone. Hence, zone '{}' successfully verified".format(zone))
            return True
        else:
            print("The PubKSK digest(s) of the '{}' zone cannot be verified by the DS record from its parent zone. Hence, "
            "DNSSec verification failed for zone '{}'".format(zone, zone))
            return False

def is_dnskey_rrset_verified(dnskey_rrset, dnskey_rrsig):
    try:
        dns.dnssec.validate(rrset = dnskey_rrset, rrsigset = dnskey_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
    except dns.dnssec.ValidationFailure as e:
        print("DNSSec verification failed during DNSKey RRSet Verification for '{}' zone: {}\n".format(dnskey_rrset.name.to_text(), e))
        return False
    else:
        print("Found {} DNSKey record(s) for zone '{}', which has been verified with its corresponding RRSig by the PubKSK".format(
            len(dnskey_rrset.items), dnskey_rrset.name.to_text()))
        return True

def is_ds_or_a_rrset_verified(zone_rrset, zone_rrsig, dnskey_rrset):
    try:
        dns.dnssec.validate(rrset = zone_rrset, rrsigset = zone_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
    except dns.dnssec.ValidationFailure as e:
        print("DNSSec verification failed during DS/A RRSet Verification for '{}' zone: {}\n".format(dnskey_rrset.name.to_text(), e))
        return False
    else:
        print("Found {} DS/A record(s) for zone '{}', which has been verified with its corresponding RRSig by the PubZSK\n".format(
            len(zone_rrset.items), dnskey_rrset.name.to_text()))
        return True

# Implements the DNSSec core verification logic
def dnssec_validated(dns_response, dnskey_response, parent_ds_rrset, contains_a_record):
    # Fetch DNSKey RRSet(Contains PubKSK + PubZSK for the zone) and its RRSig for the name server in the current zone from the Answer 
    # section of the DNSSec response returned for that zone.
    dnskey_rrsig = get_rrsig(dnskey_response.answer)
    dnskey_rrset, ksk = get_dnskey_rrset_and_ksk(dnskey_response.answer)
    
    # For all zones other than the Authoritative name server (which returns the actual IP that resolves to the query domain name),
    # return the DS RRSet(Contains hashed PubKSK for the next/child zone in the hierarchy) and its RRSig from the Authority Section of
    # the DNSSec response. For the Authoritative name server, return A records + RRsig from Answer Section of the DNSSec response.
    if contains_a_record:
        rr_section = dns_response.answer
        rrset_func = get_rrset_a
    else:
        rr_section = dns_response.authority
        rrset_func = get_rrset_ds
    zone_rrsig = get_rrsig(rr_section)
    zone_rrset = rrset_func(rr_section)

    # If a domain does not support DNSSec, its parent zone will not contain a DS record containing its PubKSK
    if zone_rrset == None:
        print("Could not find the DS record for the child zone from the parent '{}' zone. Hence, DNSSEC "
            "not supported by this domain".format(parent_ds_rrset.name.to_text()))
        return False, zone_rrset

    # Returns true, that is, DNSSec has been successfully implemented for a domain only if all of the below 3 conditions are met:
    # 1. The zone is verified by matching the hash of the PubKSK of the current/child zone stored in the DNSKey RRSet with either the
    #    content of the DS record received previously from the parent zone (in case of iterative queries to all TLD/NS server) or the root
    #    anchor keys (in case of iterative query to a root server)
    # 2. The zone's DNSKey RRSet is verified by successfully decrypting its corresponding RRSig using the zone's PubKSK
    # 3. The zone's DS/A RRSet is verified by successfully decrypting its corresponding RRSig using the zone's PubZSK
    dnssec_valid = is_zone_verified(parent_ds_rrset, ksk) and \
                    is_dnskey_rrset_verified(dnskey_rrset, dnskey_rrsig) and \
                    is_ds_or_a_rrset_verified(zone_rrset, zone_rrsig, dnskey_rrset)
    
    return dnssec_valid, zone_rrset

def a_record_resolved(answer):
    return next((True for rrset in answer if rrset.rdtype == dns.rdatatype.A), False)

# Iterative Query: Single query to a DNS Server (Root/TLD/Name/Authoritative) to get the IP address of the DNS server in the immediate
# next hierarchy, until we eventually resolve the query domain IP address. We make a series of iterative queries to different DNS servers
# from the machine that runs this code, as opposed to the traditional implementation where the resolution task is handed over to a local 
# DNS server that uses recursive queries instead.
def iterative_resolve(domain_name, rd_type, name_server, dnssec_flag, time_out = QUERY_TIMEOUT):
    domain_name = dns_name.from_text(domain_name)
    query = dns_message.make_query(qname = domain_name, rdtype = rd_type, want_dnssec = dnssec_flag)
    try:
        dns_response = dns_query.udp(q = query, where = name_server, timeout = time_out)
        return dns_response
    except Exception as e:
        raise e

# Extended the code for mydig_resolver() method in mydig.py to add DNSSec verification logic to the resolution process
def mydig_resolver(domain_name, rd_type, resolve_cname = False, return_A_record = False):
    dns_response = None
    
    for root_server in root_servers:
        try:
            # Start from the root '.' DNS zone
            root_dnskey_response = iterative_resolve('.', dns.rdatatype.DNSKEY, name_server = root_server, dnssec_flag = True)
            root_dns_response = iterative_resolve(domain_name, rd_type, name_server = root_server, dnssec_flag = True)
            dns_response = root_dns_response
        except Exception as e:
            print("Error when fetching DNSKey from Root Server {}. Error: {}".format(root_server, e))
            continue

        contains_a_record = a_record_resolved(root_dns_response.answer)
        root_validated, root_ds_rrset = dnssec_validated(root_dns_response, root_dnskey_response, None, contains_a_record)
        if not root_validated:
            exit(0)
        
        parent_ds_rrset = root_ds_rrset
        while(not dns_response.answer):
            # First read from Additional section which contains all the IPs of the next name servers which can be queried in the hierarchy
            if len(dns_response.additional) > 0:
                for rrset in dns_response.additional:
                    # Consider only IPv4 addresses (Ignoring IPv6 which have 'AAAA' type)
                    if rrset[0].rdtype == dns.rdatatype.A:
                        next_ns_ip_addr = rrset[0].address
                        try:
                            # Query the TLD / next set of name servers in the hierarchy after verifying the DNSSec information
                            ns_dnskey_response = iterative_resolve(parent_ds_rrset.name.to_text(), dns.rdatatype.DNSKEY,
                                name_server = next_ns_ip_addr, dnssec_flag = True)
                            ns_dns_response = iterative_resolve(domain_name, rd_type, name_server = next_ns_ip_addr, dnssec_flag = True)
                            
                            contains_a_record = a_record_resolved(ns_dns_response.answer)
                            ns_validated, ns_ds_rrset = dnssec_validated(ns_dns_response, ns_dnskey_response, parent_ds_rrset, contains_a_record)
                            if not ns_validated:
                                exit(0)
                            parent_ds_rrset = ns_ds_rrset

                            # DNSSec was successfully validated for this zone. Now parse the DNS record to continue the resolution process
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
                    print("Iteratively resolving IP of Authoritative Name Server {}".format(ns_domain_name))
                    ns_dns_response = mydig_resolver(ns_domain_name, 'A', return_A_record = True)
                    # If we are not resolving the CName, then query the IP address obtained
                    if not resolve_cname:
                        for auth_rrset in ns_dns_response.answer:
                            auth_ip_addr = auth_rrset[0].address
                            print("IP address for Authoritative Name Server {} was found to be {}".format(ns_domain_name, auth_ip_addr))
                            try:
                                # Finally, get the IP of the query domain from the authoritative name server
                                auth_dnskey_response = iterative_resolve(parent_ds_rrset.name.to_text(), dns.rdatatype.DNSKEY,
                                name_server = auth_ip_addr, dnssec_flag = True)
                                auth_dns_response = iterative_resolve(domain_name, rd_type, name_server = auth_ip_addr, dnssec_flag = True)

                                contains_a_record = a_record_resolved(auth_dns_response.answer)
                                auth_validated, auth_ds_rrset = dnssec_validated(auth_dns_response, auth_dnskey_response, parent_ds_rrset, contains_a_record)
                                if not auth_validated:
                                    exit(0)

                                parent_ds_rrset = auth_ds_rrset
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
                            auth_dns_response = iterative_resolve(cname_domain_name, rd_type, name_server = authoritative_ip)
                            if not auth_dns_response.answer and auth_dns_response.authority:
                                if dns.rdatatype.from_text(rd_type).value != dns.rdatatype.A:
                                    dns_response.authority.extend(auth_dns_response.authority)
                                else:
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
    
    op_str += ";; Query time: {} msec\n".format(int(tt * 1000))
    op_str += ";; SERVER: {}\n".format(hostname)
    op_str += ";; WHEN: {}\n".format(dt.now().strftime("%a %b %d %H:%M:%S EDT %Y"))
    op_str += ";; MSG SIZE  rcvd: {}\n".format(sys.getsizeof(dns_response.to_text()))
    
    return op_str


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Please enter 2 arguments, where the first is the domain name to resolve, and second is the RR type (can be one of A, NS or MX)")
        exit(0)
    
    #domain_name = 'paypal.com'
    #rdtype = 'A'
    domain_name = sys.argv[1]
    rdtype = sys.argv[2]
    if rdtype not in ['A', 'NS', 'MX']:
        print("Please ensure the RR type is one of A, NS or MX")
    
    start = time.time()
    dns_response = mydig_resolver(domain_name, rdtype)
    tt = time.time() - start

    print(dig_output(domain_name, dns_response, tt))

#print(mydig_resolver('verisigninc.com', 'A'))
#print(mydig_resolver('cnn.org', 'A'))
#print(mydig_resolver('dnssec-failed.org', 'A'))