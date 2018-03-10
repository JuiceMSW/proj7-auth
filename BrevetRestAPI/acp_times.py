"""
Open and close time calculations
for ACP-sanctioned brevets
following rules described at https://rusa.org/octime_alg.html
and https://rusa.org/pages/rulesForRiders
"""
import arrow

#  Note for CIS 322 Fall 2016:
#  You MUST provide the following two functions
#  with these signatures, so that I can write
#  automated tests for grading.  You must keep
#  these signatures even if you don't use all the
#  same arguments.  Arguments are explained in the
#  javadoc comments.
#
distance_and_max_speed = [(200.0, 34.0), (400.0, 32.0), (600.0, 30.0), (1000.0, 28.0), (1300.0, 26.0)]
distance_and_min_speed = [(600.0, 15.0), (1000.0, 11.428), (1300, 13.333)]

def open_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
       brevet_dist_km: number, the nominal distance of the brevet
           in kilometers, which must be one of 200, 300, 400, 600,
           or 1000 (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string indicating
           the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control open time.
       This will be in the same time zone as the brevet start time.
    """


    # ERRORS
    if control_dist_km > brevet_dist_km * 1.2:
      return "Error : Control Distance ({}) is more than 20% longer than Brevet Distance ({})".format(control_dist_km, brevet_dist_km)

    if control_dist_km < 0:
      return "Error : Control Distances must be non-negative"

    """
      If Control Distance is greater than Brevet Distance by less than 20%,
      it outputs the same time as if the Control Control was the Brevet Distance
    """
    if control_dist_km > brevet_dist_km:
      control_dist_km = brevet_dist_km

    total_time = 0.0
    total_traveled = 0.0

    for test in distance_and_max_speed:
      distance, max_speed = test
      if control_dist_km >= distance:
        total_time += (distance - total_traveled) / max_speed
        total_traveled = distance
      else:
        total_time += (control_dist_km - total_traveled) / max_speed
        break

    total_hours = int(total_time)
    total_minutes = int((total_time - total_hours) * 60)
    total_seconds = round(((total_time - total_hours) * 60 - total_minutes) * 60, 6)
    iso_formated_time = arrow.get(brevet_start_time + ":00", "YYYY-MM-DD HH:mm:ss")
    iso_formated_time = iso_formated_time.shift(hours=+total_hours, minutes=+total_minutes, seconds=+total_seconds)
    
    return iso_formated_time.isoformat()

def close_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
          brevet_dist_km: number, the nominal distance of the brevet
          in kilometers, which must be one of 200, 300, 400, 600, or 1000
          (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string indicating
           the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control close time.
       This will be in the same time zone as the brevet start time.
    """

    # ERRORS
    if control_dist_km > brevet_dist_km * 1.2:
      return "Error : Control Distance ({}) is more than 20% longer than Brevet Distance ({})".format(control_dist_km, brevet_dist_km)

    if control_dist_km < 0:
      return "Error : Control Distances must be non-negative"

    # Close Time at Start is 1 Hour after Start Time
    if control_dist_km == 0:
      iso_formated_time = arrow.get(brevet_start_time + ":00", "YYYY-MM-DD HH:mm:ss")
      iso_formated_time = iso_formated_time.shift(hours=+1)

      return iso_formated_time.isoformat()

    """
      If Control Distance is greater than Brevet Distance by less than 20%,
      it outputs the same time as if the Control Control was the Brevet Distance
    """
    if control_dist_km > brevet_dist_km:
      control_dist_km = brevet_dist_km

    total_time = 0.0
    total_traveled = 0.0

    for test in distance_and_min_speed:
      distance, max_speed = test
      if control_dist_km >= distance:
        total_time += (distance - total_traveled) / max_speed
        total_traveled = distance
      else:
        total_time += (control_dist_km - total_traveled) / max_speed
        break

    total_hours = int(total_time)
    total_minutes = int((total_time - total_hours) * 60)
    total_seconds = round(((total_time - total_hours) * 60 - total_minutes) * 60, 6)
    iso_formated_time = arrow.get(brevet_start_time + ":00", "YYYY-MM-DD HH:mm:ss")
    iso_formated_time = iso_formated_time.shift(hours=+total_hours, minutes=+total_minutes, seconds=+total_seconds)
    
    return iso_formated_time.isoformat()