from ipaddress import IPv4Address

"""
Converts a string IP address to its integer form

@param key the string IP address (e.g. '127.0.0.1')
@return the IP address as a 32-bit integer
"""
def ip_to_int(key):
    if isinstance(key, int): return key
    return int(IPv4Address(str(key)))

sample_ARP = {'127.0.0.1':'01:a','127.0.0.2':'01:b','127.0.0.3':'01:c'}
print(sample_ARP.keys())
# # ip_str = {'127.0.0.1':2130706433, '111'}
# ip_int = ip_to_int(ip_str)
# print(ip_int)
# print(lambda keys: [ip_to_int(ip_str)])

# KEYS_TO_NUMERIC = {
#     lambda keys
# }
# KEYS_TO_NUMERIC = {
#     # E.g.
#     # ARP_CACHE_TABLE_NAME:
#     #    # arp_cache_table is keyed by an IP address
#     lambda keys: [ip_to_int(keys[0])],
# }


