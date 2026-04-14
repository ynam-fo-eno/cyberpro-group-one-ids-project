# This is the entry point of our code.
# Well, once we run the command in our README to
# make the logs first.

from driver_files.ids_engine import IntrusionDetectionSystem

# Run the IDS when script is executed
if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.run()