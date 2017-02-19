
		
def dl_file_pbar(source_url, dest_path, sess=None, autoname=False, **kw):
    from urllib.parse import urlparse, unquote
    if sess is None:
        stream = requests.get(source_url, stream=True, **kw)
    else:
        stream = sess.get(source_url, stream=True, **kw)

    try:
        total_bytes = int(stream.headers['content-length'])
    except:
        total_bytes = None

    if autoname:
        # dest_path is a directory path, get the filename automatically
        try:
            dest_path = Path(dest_path) / re.findall("filename=(.+)", r.headers['content-disposition'])[0]
            if fname is None:
                raise Exception()
        except:
            dest_path = Path(dest_path) / os.path.basename(unquote(urlparse(source_url).path))

    with open(str(dest_path), 'wb') as dest_file:
        with tqdm(total=total_bytes) as pbar:
            for chunk in stream.iter_content():
                dest_file.write(chunk)
                pbar.update(len(chunk))

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")