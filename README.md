# CYBERPRO MODULE 1, JAN 2-26 SEMESTER: TERMINAL BASED INTRUSION DETECTION SYSTEM BY GROUP 1
    Created in April 2026, this may be considered the capstone project done by the 
    five great gentlemen and ladies to sum up what we were taught- and indeed what
    we researched on our own- to make a simple but effective intrusion detection
    system entirely in python and using various handy libraries such as timedelta
    and datetime to handle getting the date and time for all the logs cleanly.


 ## contributors
    1. Churchill Wasike -

    2. Dianah Nturibi -
    
    3. Elvin Nyamoita-
    
    4. Shaltone Rimba Otieno - 
    
    5. Timothy Mwenda -


## This project will achieve the following:
  ->Log Creation and monitoring: Our system uses its logs_generator.py to
   assess the IP addresses given and send output to a sample_logs.txt file,
   saved in our logs subfolder.

  ->Brute Force Detection: The IDS correctly identifies 5 failed attempts 
   within a 2-minute window .

  ->IP Tracking: You are accurately extracting and counting attempts per IP address 
   both for failed logins and too many logins in the time-frame.

  ->Alert System: This terminal IDS is a dual-channel system that prints terminal alerts
   and triggers actual email notifications.

  ->Basic Reporting: The engine generates a timestamped report file summarizing 
   attack counts and top offenders.

  ->System Architecture:Each module deal with its own issue (detectors handle brute 
   force attacks and suspect activity, driver_files save the logs to a .txt file 
   and create a report for them and so on), following OOP system design principles.


 ## How to run it 
   1.Clone this project as follows:
        `git clone https://github.com/ynam-fo-eno/cyberpro-group-one-ids-project`


   2.Use these commands in your ROOT directory (like don't be in the utils or driver_files folder plz! ) to:
   A. Make the log file your IDS will read from:
      `py -m driver_files.log_generator`
   
   (It's worth noting that now that almost every file is in its own subfolder, the -m flag is needed so your interpreter knows to coalesce ALL your
   subfolders and respective Python code as one project. Without it, chances are it'll fail even tho the code would work well otherwise.)

   B. Make the IDS make the alerts on the console and even send the listed emails receive said alerts:
      `py main.py`
    



