import pymssql, struct, argparse

parser = argparse.ArgumentParser(add_help=True, description="Enumerate domain users/groups using mssql connection.")
parser.add_argument('-ip', action='store', required=True, help='IP from MSSQL Server')
parser.add_argument('-d', action='store', required=True, help='Domain from MSSQL Server')
parser.add_argument('-u', action='store', required=True, help='Username for MSSQL Server')
parser.add_argument('-p', action='store', required=True, help='Password for MSSQL Server')
parser.add_argument('-db', action='store', default='tempdb', help='Database to connect (Default: tempdb)')
parser.add_argument('-start-rid', type=int, default=1100, help='Start RID for brute force (Default: 1100)')
parser.add_argument('-max-failures', type=int, default=5, help='Max consecutive failures to stop (Default: 5)')

args = parser.parse_args()

conn = pymssql.connect(args.ip, args.u, args.p, args.db)
cursor = conn.cursor(as_dict=True)

def sid_to_str(sid):
    revision = sid[0]
    number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]
    
    domain_sub_ids = sub_ids[:-1]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in domain_sub_ids]))

def extract_domain(cursor):
    cursor.execute(f"select sys.fn_varbintohexstr(SUSER_SID('{args.ip}\\Administrator')) as Domain;")
    row = cursor.fetchone()
    if row:
        sid = row['Domain']
        return sid_to_str(bytes.fromhex(sid[2:]))
    return None

def rid_brute(domain_sid, start_rid=1100, max_failures=5):
    rid = start_rid
    consecutive_failures = 0

    print(f"\n[+] Extracting AD Objects...\n")

    while consecutive_failures < max_failures:
        sid = f"{domain_sid}-{rid}"
        try:
            cursor.execute(f"select SUSER_SNAME(SID_BINARY(N'{sid}')) as UserName;")
            row = cursor.fetchone()
            if row and row['UserName']:
                print(f"{row['UserName']}")
                consecutive_failures = 0
            else:
                consecutive_failures += 1
        except Exception as e:
            print(f"Error querying SID {sid}: {e}")
            consecutive_failures += 1

        rid += 1

    print(f"\nExtraction stopped after reaching a sequence of {max_failures} consecutive empty results.")

domain_sid = extract_domain(cursor)
if domain_sid:
    rid_brute(domain_sid, start_rid=args.start_rid, max_failures=args.max_failures)

conn.close()
