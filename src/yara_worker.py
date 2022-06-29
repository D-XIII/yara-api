import glob
import yara
from os.path import join, dirname


class yaraWorker():
    rules = None

    def __init__(self):
        self.filepaths = []

        for file in glob.iglob(join(dirname(__file__), 'rules/*/*.yar'), recursive=True):
            self.filepaths.append(file)

        filepaths_dict = {file: file for file in self.filepaths}

        self.rules = yara.compile(filepaths=filepaths_dict)

    def analyse(self, file):
        strings = []
        matches = []
        self.matches = self.rules.match(data=file.read())
        return self.matches
