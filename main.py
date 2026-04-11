from driver_files.ids_engine import IntrusionDetectionSystem

# Run the IDS when script is executed
if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.run()