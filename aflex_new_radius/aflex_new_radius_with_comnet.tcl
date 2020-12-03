when CLIENT_DATA {
  # read value of attribute id 40
  binary scan [RADIUS::avp 40] I1 acct_code
  set allavp [RADIUS::avp]
  set result_vsa ""
  # Check Status type 'start' or 'stop'
  if {$acct_code == 1} { 
	set Status_Type "Start"
  } else {
	set Status_Type "Stop"
  }
  append result_vsa "$Status_Type | "

  #Sort all avp from lowest to highest
  set all_avp [lsort -dictionary $allavp ]

	#for loop for read all avp in radius packets
   for {set i 0} { $i < [llength $all_avp] } { incr i } {
   
	#check avp = 26
	   if { [lindex $all_avp $i 0] == 26 } {
		
	#binary scan avp 26 in position 2(value) and 'x4' is move forward 4 byte then read value with binary scan 'c' format 1 byte and put in variable 'vsa'.
	#binary scan 'c' format is data will turned into count 8-bit signed integers.
            binary scan [lindex $all_avp $i 2] x4c1 vsa	

           #convert data from signed integers to unsigned integers.
            set usign_vsa [expr ( $vsa + 0x100 ) % 0x100]

			#binary scan format 'x' is move cursor forward || ex. 'x6' is move cursor forward 6 byte
			#The switch statement is matches its string argument against each of the pattern arguments in order and use instead of if - elseif...elseif.....elseif.

			switch [lindex $usign_vsa ] {
			
			#check vsa type = 1, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 8-bits (1 byte) 4 times to get IPv4.
			1 {
				binary scan [lindex $all_avp $i 2] x6c1c1c1c1 oct4 oct3 oct2 oct1
				append result_vsa "$oct4.$oct3.$oct2.$oct1 | "
			}
			
			#check vsa type = 2, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 8-bits 1 byte 4 times.
			2 {
				binary scan [lindex $all_avp $i 2] x6c1c1c1c1 oct4 oct3 oct2 oct1
				append result_vsa "$oct4.$oct3.$oct2.$oct1 | "
			}
			
			#check vsa type = 4, read data at potition 2 (value) and move cursor forward 6 byte and read all data as string and put result in variable 'vsa4_value'.
			4 {
				binary scan [lindex $all_avp $i 2] x6a* vsa4_value
				append result_vsa "$vsa4_value | "
			}
			
			#check vsa type = 38, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 32-bits 1 byte and put result in variable 'vsa38_value'.
			#check value in variable 'vsa38_value'. If value in 'vsa38_value' equal 11 set new variable 'vsa38' equal "DSL" 
			38 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa38_value
                                  if {$vsa38_value == 11} {
                                  set vsa38 "DSL"
				      append result_vsa "$vsa38 | "
                                  } else {
			              append result_vsa "$vsa38_value | "
                                      }
			}

			#check vsa type = 62, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 32-bits 1 byte and put result in variable 'vsa62_value'.
			62 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa62_value
				append result_vsa "$vsa62_value | "
			}

			#check vsa type = 87, read data at potition 2 (value) and move cursor forward 6 byte and read all data as string and put result in variable 'Qos_Policing_Profile_Name'.
			87 {
				binary scan [lindex $all_avp $i 2] x6a* Qos_Policing_Profile_Name
				append result_vsa "$Qos_Policing_Profile_Name | "
			}

			#check vsa type = 88, read data at potition 2 (value) and move cursor forward 6 byte and read all data as string and put result in variable 'Qos_Metering_Profile_Name'.
			88 {
				binary scan [lindex $all_avp $i 2] x6a* Qos_Metering_Profile_Name
				append result_vsa "$Qos_Metering_Profile_Name | "
			}

			#check vsa type = 98, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 32-bits 1 byte and put result in variable 'vsa98_value'.
			#check value in variable 'vsa98_value'. If value in 'vsa38_value' equal 2 set new variable 'vsa98' equal "SmartEdge-800"
			98 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa98_value
                                  if {$vsa98_value == 2} {
                                  set vsa98 "SmartEdge-800"
				      append result_vsa "$vsa98 | "
                                  } else {
			              append result_vsa "$vsa98_value | "
                                      }
			}

			#check vsa type = 112, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'vsa112_value'.
			112 {
				binary scan [lindex $all_avp $i 2] x6a* vsa112_value
				append result_vsa "$vsa112_value | "
			}

			#check vsa type = 113, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'Session_Traffic_Limit'.
			113 {
				binary scan [lindex $all_avp $i 2] x6a* Session_Traffic_Limit
				append result_vsa "$Session_Traffic_Limit | "
			}

			#check vsa type = 145, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'vsa145_value'.
			145 {
				binary scan [lindex $all_avp $i 2] x6a* vsa145_value
				append result_vsa "$vsa145_value | "
			}

			#check vsa type = 190, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'Service_Name'.
			190 {
				binary scan [lindex $all_avp $i 2] x6a* Service_Name
				append result_vsa "$Service_Name | "
			}

			#check vsa type = 196, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'Dynamic_QoS_Param'.			
			196 {
				binary scan [lindex $all_avp $i 2] x6a* Dynamic_QoS_Param
				append result_vsa "$Dynamic_QoS_Param | "
			}

			#check vsa type = 207, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'rb_ipv6_dns'.						
			207 {
				binary scan [lindex $all_avp $i 2] x6a* rb_ipv6_dns
				append result_vsa "$rb_ipv6_dns | "
			}

			#check vsa type = 208, read data at potition 2 (value) and move cursor forward 6 byte then read all data as string and put result in variable 'rb_ipv6'.
			208 {
				binary scan [lindex $all_avp $i 2] x6a* rb_ipv6
				append result_vsa "$rb_ipv6 | "
			}

			#check vsa type = 212, read data at potition 2 (value) and move cursor forward 6 byte then read data as signed integer 32-bits 1 byte and put result in variable 'delegated_max_prefix'.
			212 {
				binary scan [lindex $all_avp $i 2] x6I1 delegated_max_prefix
				append result_vsa "$delegated_max_prefix | "
			}
			default {
				append result_vsa "Value not in list cut [lindex $all_avp $i 2] | "
			}
		  }
		 
	   } else {
			switch [lindex $all_avp $i 0] {

			#Check radius avp = 1, read data at potition 2 (value) then read all data as string and put result in variable 'username'.
                          1 {
				 binary scan [lindex $all_avp $i 2] A* username
			 append result_vsa "$username | "
			   }

			#Check radius avp = 2, read data at position 2 (value) then read all data as hexadecimal and put result in variable 'password'.
                          2 {
				 binary scan [lindex $all_avp $i 2] H* password
			 append result_vsa "$password | "
			   }

			#Check radius avp = 4, read data at potition 2 (value) then read all data as string and put result in variable 'nas_ip'.
                          4 {
				 binary scan [lindex $all_avp $i 2] A* nas_ip
			 append result_vsa "$nas_ip | "
			   }

			#Check radius avp = 5, read data at potition 2 (value) then read all data as string and put result in variable 'nas_ip'.
                          5 {
				 binary scan [lindex $all_avp $i 2] A* nas_port
			 append result_vsa "$nas_port | "
			   }

			#check radius avp = 6, read data at potition 2 (value) then read all data as string and put result in variable 'service_type'.
			#check value in variable 'service_type'. If value in 'service_type' equal 2 set new variable 'serv_type' equal "Frame".	
                          6 {
				 binary scan [lindex $all_avp $i 2] A* service_type
                                  if {$service_type == 2} {
                                  set serv_type "Frame"
			              append result_vsa "$serv_type | "
                                  } else {
			              append result_vsa "$service_type | "
                                      }
			   }

			#check radius avp = 7, read data at potition 2 (value) then read all data as string and put result in variable 'frame_proto'.
			#check value in variable 'frame_proto'. If value in 'frame_proto' equal 1 set new variable 'frame_pt' equal "PPP".
                          7 {
				 binary scan [lindex $all_avp $i 2] A* frame_proto
                                  if {$frame_proto == 1} {
                                  set frame_pt "PPP"
			              append result_vsa "$frame_pt | "
                                  } else {
			              append result_vsa "$frame_proto | "
                                      }
			   }

			#Check radius avp = 8, read data at potition 2 (value) then read all data as string and put result in variable 'frame_ip'.
                          8 {
				 binary scan [lindex $all_avp $i 2] A* frame_ip
			 append result_vsa "$frame_ip | "
			   }

			#Check radius avp = 9, read data at potition 2 (value) then read all data as string and put result in variable 'frame_netmask'.
                          9 {
				 binary scan [lindex $all_avp $i 2] A* frame_netmask
			 append result_vsa "$frame_netmask | "
			   }

			#Check radius avp = 25, read data at potition 2 (value) then read all data as hexadecimal and put result in variable 'frame_netmask'.
			25 {
				 binary scan [lindex $all_avp $i 2] H* Class
			 append result_vsa "$Class | "
			   }

			#Check radius avp = 27, read data at potition 2 (value) then read all data as string and put result in variable 'sess_timeout'.
			27 {
				 binary scan [lindex $all_avp $i 2] A* sess_timeout
			 append result_vsa "$sess_timeout | "
			   }

			#Check radius avp = 31, read data at potition 2 (value) then read all data as string and put result in variable 'idel_timeout'.
                        28 {
				 binary scan [lindex $all_avp $i 2] A* idel_timeout
			 append result_vsa "$idel_timeout | "
			   }

			#Check radius avp = 31, read data at potition 2 (value) then read all data as string and put result in variable 'cs_id'.
			31 {
			 binary scan [lindex $all_avp $i 2] A* cs_id
			 append result_vsa "$cs_id | "
			   }

			#Check radius avp = 32, read data at potition 2 (value) then read all data as string and put result in variable 'nas_iden'.
			32 {
			 binary scan [lindex $all_avp $i 2] A* nas_iden
			 append result_vsa "$nas_iden | "
			   }

			#Check radius avp = 40, read data at potition 2 (value) then read all data as string and put result in variable 'Acct_status'.
			40 {
			 binary scan [lindex $all_avp $i 2] A* Acct_status
			 append result_vsa ""
			   }

			#Check radius avp = 41, read data at potition 2 (value) then read data as signed integer 32-bits 1 byte and put result in variable 'Acct_Delay_Time'.
			41 {
			 binary scan [lindex $all_avp $i 2] I1 Acct_Delay_Time
			 append result_vsa "$Acct_Delay_Time | "
			   }

			#Check radius avp = 44, read data at potition 2 (value) then read all data as string and put result in variable 'Acct_session_id'.
			44 {
			 binary scan [lindex $all_avp $i 2] A* Acct_session_id
			 append result_vsa "$Acct_session_id | "
			   }

			#Check radius avp = 45, read data at potition 2 (value) then read data as signed integer 32-bits 1 byte and put result in variable 'acct_authentic'.
			#check value in variable 'acct_authentic'. If value in 'acct_authentic' equal 1 set new variable 'acc_authen' equal "Radius".
			45 {
				 binary scan [lindex $all_avp $i 2] I1 acct_authentic
                                  if {$acct_authentic == 1} {
                                  set acc_authen "Radius"
                                      append result_vsa "$acc_authen | "
                                  } else {
			              append result_vsa "$acct_authentic | "
                                      }
			   }

			#Check radius avp = 55, read data at potition 2 (value) then read all data as signed integer 32-bits and put result in variable 'Event_Timestamp'.
			#Convert value in variable 'Event_Timestamp' to time format and put result in new variable 'systemtime' 
			55 {
				 binary scan [lindex $all_avp $i 2] I* Event_Timestamp
				 set systemTime [clock format $Event_Timestamp -format {%b %d, %Y %H:%M:%S }]
				 append result_vsa "$systemTime | "
			   }

			#Check radius avp = 61, read data at potition 2 (value) then read all data as string and put result in variable 'nas_port_ty'.
			#Check value in variable 'nas_port_ty'. If value in 'nas_port_ty' equal 5 set new variable 'nas_port_type' equal "Virtual".
			61 {
				 binary scan [lindex $all_avp $i 2] A* nas_port_ty
                                  if {$nas_port_ty == 5} {
                                  set nas_port_type "Virtual"
                                      append result_vsa "$nas_port_type | "
                                  } else {
			              append result_vsa "$nas_port_ty | "
                                      }
			   }

			#Check radius avp = 85, read data at potition 2 (value) then read all data as signed integer 32-bits and put result in variable 'Acct_Interim_Interval'.
			85 {
				 binary scan [lindex $all_avp $i 2] I1 Acct_Interim_Interval
			 append result_vsa "$Acct_Interim_Interval | "
			   }

			#Check radius avp = 87, read data at potition 2 (value) then read all data as string and put result in variable 'nas_port_id'.
			87 {
				 binary scan [lindex $all_avp $i 2] A* nas_port_id
			 append result_vsa "$nas_port_id | "
			   }

			#Check radius avp = 96, read data at potition 2 (value) then read all data as hexadecimal and put result in variable 'Framed_Interface_Id'.
			96 {
				 binary scan [lindex $all_avp $i 2] H* Framed_Interface_Id
			 append result_vsa "$Framed_Interface_Id | "
			   }

			#Check radius avp = 97, read data at position 2 (value) then skip 1 byte read data as integer-32 bit 1 byte and read data as hexadecimal 4 bytes 8 times, and put result in 9 variables in order.
			97 {
				 binary scan [lindex $all_avp $i 2] x1c1H4H4H4H4H4H4H4H4 IPv6_Prefix 1st 2nd 3rd 4th 5th 6th 7th 8th
			 append result_vsa "$1st:$2nd:$3rd:$4th:$5th:$6th:$7th:$8th/$IPv6_Prefix | "
			   }
			default {
			 append result_vsa "[lindex $all_avp $i 2] | "
				} 
			 }
		  }
 }
  log "$result_vsa"
}
