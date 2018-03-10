# Project 7: Brevet time calculator service (Now With Users!)

## Author Information

Name: Michael Welch  
Email: michael.welch.99@gmail.com

## About

The Brevet Control Time Calculator uses the specifications given by the ACP.

The Open and Close Times are calculated using the table specified by the ACP found here - https://rusa.org/octime_alg.html

The Official ACP Form Based Calculator is located here - https://rusa.org/octime_acp.html

## Update

Now has different users with username and hashed password stored in database.

New UI

Database and RESTFUL API have per user data

Now implements RESTFUL API  

### How to Create Account

Fill out the fields with username and password. Hit Register New User.  

If successful, it will display in text underneath.  

After registering, log back in with username and password.  

### How to Use UI

Enter in all control distances, and brevet information.  

Then hit the Submit to Database Button.  It will pop up with an alert.  

Then select choices for output format.  

Finally, hit display database to look at data in the formate selected above.  

### How to Expose Data

Adding the following extensions to the URL will output data in either JSON or csv format.  

*/listAll*  
List all open and close times from database (default : JSON Format, can be specified with appending /json or /csv to URL)

*/listOpenOnly*  
List only open times from database (default : JSON Format, can be specified with appending /json or /csv to URL)

*/listCloseOnly*  
List only close times from database (default : JSON Format, can be specified with appending /json or /csv to URL)

*NEW* **REQUIRED**  
Now REQUIRES username input.  
Usage: Append ?username=username to display info from database.

*Sort Results by Shortest Times*  
The 'top' URL variable can be changed to display only top x times.  Works with any previous URL.  
Usage: Append ?username=username&top=x to display top x times  

## Specifics

Calculating the Open and Close Times is done by taking the Control Distance and dividing by the number specified by the table.  
Ex: 150km

    Max Speed from 0 - 200km = 34: Open Time = 150/34 = 04H24M
    Min Speed from 0 - 600km = 15: Close Time = 150/15 = 10H00M

If a Control Distance spans over multiple ranges in the table then the Open and Close Times are calculated as follows.  
Ex: 650km

    Max Speed from 0 - 200km = 34: 200/34 = 05H52M
    Max Speed from 200 - 400km = 32: 200/32 = 06H15M
    Max Speed from 400 - 600km = 30: 200/30 = 06H40M
    Max Speed from 600 - 1000km = 28: 50/28 = 01H47M
    Open Time = 05H52M + 06H15M + 06H40M + 01H47M = 20H34M

    Min Speed from 0 - 600km = 15: 600/15 = 40H00M
    Min Speed from 600 - 1000km = 11.428: 50/11.428 = 04H22M
    Close Time = 40H00M + 04H22M = 44H22M

The Maximum Control Distance is 20% Longer than the Brevet Distance (Ex: For a 200km Brevet, 240km is the Maximum Control Distance).  
For any Control in this Range, the Open and Close times are equal to the Brevet Distance Open and Close Times.

For a Control at 0km, the Open Time is equal to the Brevet Start Time and the Close Time is equal to the Brevet Start Time plus 1 Hour.  
This means that Controls at small distanes could have Closing Times earlier than the Closing Time at the Control at 0km.

