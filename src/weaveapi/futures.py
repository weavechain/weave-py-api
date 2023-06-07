import time

class CompletableFuture:
    def __init__(self, data):
        self.data = data
        self.completed = data is not None

    def done(self, data):
        self.data = data
        self.completed = True

    def get(self):
        while not self.completed:
            #TODO: mutex
            time.sleep(1)
        return self.data
