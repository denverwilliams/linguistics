import email
from email import policy
from email.parser import BytesParser

def process_email(fn, msg_ids):
    # Open the file in binary mode
    with open(fn, 'rb') as f:
        content = f.read()

    # Parse the email from bytes
    msg = BytesParser(policy=policy.default).parsebytes(content)
    
    # Extract message ID
    message_id = msg.get('message-id')
    if message_id in msg_ids:
        return
    msg_ids.add(message_id)
    
    # Extract and clean body
    body = _clean_body(get_body_content(msg))
    
    # Construct email information dictionary
    e = {
        "message_id": message_id,
        # Extract email addresses from 'From', 'To', and 'Cc' headers
        "from": extract_email_address(msg.get('from')),
        "to": extract_email_addresses(msg.get_all('to', [])) + extract_email_addresses(msg.get_all('cc', [])),
        "date": msg.get('date'),
        "subject": msg.get('subject'),
        "body": body,
        "attachments": [part.get_filename() for part in msg.iter_parts() if part.get_content_disposition() == 'attachment']
    }
    
    print (e)
    return e

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

def _clean_body(body):
    """Clean the email body content (custom implementation needed)."""
    # Implement your cleaning logic here
    return body

# Example usage
fn = "/home/owner/culture_test/enron/maildir/storey-g/deleted_items/104.eml"
msg_ids = set()
email_info = process_email(fn, msg_ids)
