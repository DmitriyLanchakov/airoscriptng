import subprocess

class main(object):
    def __init__(self, parent):
        self.parent = parent
        self.target_file = "{}/{}-01-reaver.txt".format(self.parent.target_dir, self.parent.config["name"])

    def scan(self, file_):
        if file_:
            subprocess.call(['wash', '-C', '-o', self.target_file, "-f", "{}/{}-01.cap".format(self.parent.target_dir, self.parent.config["name"])])
            with open(self.target_file) as reaver_file:
                targets = reaver_file.readlines()
            result = [{'bssid':t.split(' ')[0]} for t in targets[4:]]
            return result
        else:
            return []




