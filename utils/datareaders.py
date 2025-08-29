
import os
import csv
import ujson

# For *.eml files
import re
import collections
import mailparser
import unidecode

# Second Parser
import email
from email import policy
from email.parser import BytesParser



###########################################

def _get_fns_from_dir(dir_fn, ext):
    """
    Search dir and subdirs for all files with given extension
    """
    if not os.path.isdir(dir_fn):
        # Input is a filename not a dir
        return [dir_fn]
    fns = []
    for root, dirs, files in os.walk(dir_fn, topdown=False):
        fns += [os.path.join(root, fn) for fn in files if fn.split(".")[-1] == ext]
    return fns

###########################################


class CsvDataReader:

    def __init__(self, csv_fn):
        self.fns = _get_fns_from_dir(csv_fn, "csv")

    def __iter__(self):
        for fn in self.fns:
            with open(fn) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    yield row
                f.close()


###########################################


class JsonDataReader:

    """
    Expectation for these files is that 
    each individual line in the file is a
    json-serialized document
    """

    def __init__(self, json_fn):
        self.fns = _get_fns_from_dir(json_fn, "json")


    def __iter__(self):
        for fn in self.fns:
            with open(fn) as f:
                for i,line in enumerate(f):
                    d = ujson.loads(line)
                    yield d
                f.close()

    @staticmethod
    def write(docs, out_fn):
        with open(out_fn, 'w') as outf:
            for d in docs:
                outf.write(ujson.dumps(d) + "\n")
            outf.close()



###########################################




class EmlDataReader:

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.fns = _get_fns_from_dir(base_dir, "eml")
        self.internal_domain = 'enron.com'
        self.sender_frequency = collections.defaultdict(int)

    def __iter__(self):
        """
        Finds all .eml files in self.base_dir
        and subdirectories of self.base_dir.
        Does its best to parse each email before
        releasing.
        """
        # Eml exports often include duplicate emails.
        # We will try to limit the duplicates we release
        msg_ids = set()
        for fn in self.fns:
            print("Reading files!!!!!!!")
            print(fn)
            msg = None
            try:
                msg = mailparser.parse_from_file(fn)
                if msg.message_id in msg_ids:
                    continue
                msg_ids.add(msg.message_id)

                # Apply first filter: Check if sender is external and not an internal recipient
                if not self._is_internal_sender(msg) or not self._has_internal_recipient(msg):
                    continue  # Skip if email is from an external address and no internal recipients

                # Apply second filter: Check if the email is a broadcast or administrative email
                if self._is_broadcast_or_admin_email(msg):
                    continue  # Skip if email is considered a broadcast or administrative message

                # Do our best to clean the msg body
                body = self._clean_body(msg.body)
                e = {
                    "message_id": msg.message_id,
                    # Keep only email addrs, not attempted parsed names
                    "from": msg.from_[0][1],
                    # Combine to and cc fields (i.e., no distinction made
                    #   between direct messages and group messages)
                    "to": [a[1] for a in msg.to] + [a[1] for a in msg.cc],
                    "date": msg.date,
                    "subject": msg.subject,
                    "body": body,
                    "attachments": [a['filename'] for a in msg.attachments]
                }
                if not e['from'] or not e['to']:
                    continue
                yield e

            except Exception as primary_parser_exception:
                print(f"Primary parser failed with exception: {primary_parser_exception}")
                try:
                    with open(fn, 'rb') as f:
                        content = f.read()

                    # Parse the email from bytes
                    msg = BytesParser(policy=policy.default).parsebytes(content)

                    # Extract message ID
                    message_id = msg.get('message-id')
                    if message_id in msg_ids:
                        continue
                    msg_ids.add(message_id)

                    # Check external sender and internal recipient filter
                    if not self._is_internal_sender(msg) and not self._has_internal_recipient(msg):
                        continue

                    # Check broadcast or administrative email filter
                    if self._is_broadcast_or_admin_email(msg):
                        continue

                    # Extract and clean body
                    body = self._clean_body(get_body_content(msg))

                    # Construct email information dictionary
                    e = {
                        "message_id": message_id,
                        "from": extract_email_address(msg.get('from')),
                        "to": extract_email_addresses(msg.get_all('to', [])) + extract_email_addresses(msg.get_all('cc', [])),
                        "date": msg.get('date'),
                        "subject": msg.get('subject'),
                        "body": body,
                        "attachments": [part.get_filename() for part in msg.iter_parts() if part.get_content_disposition() == 'attachment']
                    }

                    if not e['from'] or not e['to']:
                        continue
                    yield e

                except Exception as fallback_parser_exception:
                    print(f"Fallback parser failed with exception: {fallback_parser_exception}")
                    # Handle the fallback failure (log or take other actions as necessary)
                    continue


    # Regexes for some common quoted text beginnings
    QUOTED_TXT_RES = [
        ## With names & email addresses
        re.compile(r"On (Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9][,]? (at )?[0-9]+:[0-9][0-9][ ]?(A|P)M[,]? [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})(\n?)>[\s]?wrote:"),
        re.compile(r"On (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9](,)? (at )?[0-9]+:[0-9][0-9] (AM|PM)?[ ]?[,]? [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})(\n?)>[\s]?wrote:"),
        re.compile(r"On 201[0-9]-[0-9][0-9]-[0-9][0-9](,)? (at )?[0-2]?[0-9]:[0-9][0-9][ ]?, [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})[\n]?>[\s]wrote:"),
        re.compile(r"On [0-9]?[0-9] (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) 201[0-9](,)? (at )?[0-9]+:[0-9][0-9][ ]?(AM|PM)?[ ]?[,]? [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})(\n?)>[\s]?wrote:"),
        ## With names but no email addresses
        re.compile(r"On (Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9](,)? (at )?[0-9]+:[0-9][0-9] (A|P)M[ ]?[,]? [ a-zA-Z\.\-\"]+[\s]*wrote:"),
        re.compile(r"On (Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9][,]? [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})(\n?)>[\s]?wrote:"),
        re.compile(r"On (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9](,)? (at )?[0-9]+:[0-9][0-9][ ]?(AM|PM)?[ ]?[,]?[ ]?[ a-zA-Z\.\-\"]+[\s]*wrote:"),
        re.compile(r"On 201[0-9]-[0-9][0-9]-[0-9][0-9](,)? (at )?[0-2]?[0-9]:[0-9][0-9][ ]?,[ ]?[ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})[\n]?>[\s]wrote:"),
        re.compile(r"On [0-9]?[0-9] (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) 201[0-9](,)? (at )?[0-9]+:[0-9][0-9][ ]?(AM|PM)?[ ]?[,]? [ a-zA-Z\.\-\"]+[\s]wrote:"),
        ## Different date format
        re.compile(r"On [0-9]?[0-9]/[0-9]?[0-9]/201[0-9] (at )?[0-2]?[0-9]:[0-9][0-9][ ]?(AM|PM)?, [ a-zA-Z\.\-\"]+[\s]<[\n]?(?:[\w._%+-]+@[\w._%+-]+\.\w{2,})[\n]?>[\s]wrote:"),
        re.compile(r"On [0-9]?[0-9]/[0-9]?[0-9]/201[0-9] (at )?[0-2]?[0-9]:[0-9][0-9][ ]?(AM|PM)?, [ a-zA-Z\.\-\"]+[\s]wrote:"),
        ## Other boundary markers
        re.compile(r"----- Original [Mm]essage -----"),
        re.compile(r"--- mail_boundary ---"),
        re.compile(r"[Ss]ent from my (iPhone|Windows|Android|mobile)"),
        re.compile(r"[Ss]ent: (Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)[,]? (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December) [0-9]+, 201[0-9](,)? (at )?[0-9]+:[0-9][0-9]"),
    ]

    def _is_internal_sender(self, msg):
        """Check if the sender is internal (based on email domain)."""
        sender = msg.from_[0][1]
        return sender.endswith(f"@{self.internal_domain}")

    def _has_internal_recipient(self, msg):
        """Check if any recipient is internal."""
        recipients = [a[1] for a in msg.to] + [a[1] for a in msg.cc]
        return any(recipient.endswith(f"@{self.internal_domain}") for recipient in recipients)

    def _is_broadcast_or_admin_email(self, msg):
        """Identify broadcast or administrative messages."""
        num_recipients = len([a[1] for a in msg.to] + [a[1] for a in msg.cc])
        if num_recipients > 5:  # A broadcast message (you can adjust the number)
            return True
        
        # Track frequency of emails from the sender
        sender = msg.from_[0][1]
        self.sender_frequency[sender] += 1

        # Administrative email logic: frequent sender, few recipients, and specific keywords
        if self.sender_frequency[sender] > 10 and num_recipients == 1:
            body = self._clean_body(msg.body)
            subject = msg.subject.lower()
            body = body.lower()
            admin_keywords = ["expense report", "approval", "reminder", "action required"]
            if any(keyword in subject or keyword in body for keyword in admin_keywords):
                return True

        return False

    def _clean_body(self, body):
        """
        This function attempts to strip quoted text 
        from an email body so that only the text actually 
        written by the email sender remains.

        Email formats are messy and heterogeneous, 
        and this function does not catch all quoted text 
        or all signatures and should not be considered a 
        "complete" (and certainly not an elegant ha!) solution. 
        We recommend testing and expanding this functionality 
        using your own data. (For example, you may also want to
        catch and remove automated messages, etc.)
        """

        body = unidecode.unidecode(body)
        # Strip quoted text
        for quot_re in self.QUOTED_TXT_RES:
            body = quot_re.split(body)[0]
        # Try to remove inserted newlines
        # to recover intended paragraph splits--
        # rough and dirty style
        lines = body.split("\n")
        chunks = []
        active_chunk = lines[0]
        for i in range(1, len(lines)):
            prev_line = lines[i-1]
            curr_line = lines[i]
            if len(prev_line) >= 65 and len(prev_line) <= 75:
                # curr_line probably used to be part of prev_line
                active_chunk += " " + curr_line
            else:
                chunks.append(active_chunk)
                active_chunk = curr_line
        chunks.append(active_chunk)
        body = "\n".join(chunks)
        body = body.replace("    ", " ")
        return body



def get_body_content(msg):
    """Return the plain text body content of the email."""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(part.get_content_charset(), errors='replace')
    else:
        return msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='replace')
    return ''

def extract_email_address(address_field):
    """Extract email address from the 'from' field."""
    if address_field:
        return email.utils.parseaddr(address_field)[1]
    return ''

def extract_email_addresses(address_field_list):
    """Extract email addresses from a list of 'to' or 'cc' fields."""
    addresses = []
    for address_field in address_field_list:
        addresses.append(email.utils.parseaddr(address_field)[1])
    return addresses
