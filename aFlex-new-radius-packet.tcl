when CLIENT_DATA {
  # read value of attribute id 40
  binary scan [RADIUS::avp 40] I1 acct_code
  set all_avp [RADIUS::avp]
  set result_vsa ""
  # Check Status type 'start' or 'stop'
  if {$acct_code == 1} { 
	set Status_Type "Start"
  } else {
	set Status_Type "Stop"
  }
  append result_vsa "$Status_Type "
   for {set i 0} { $i < [llength $all_avp] } { incr i } {
	   if { [lindex $all_avp $i 0] == 26 } {
            binary scan [lindex $all_avp $i 2] x4c1 vsa		
            set usign_vsa [expr ( $vsa + 0x100 ) % 0x100]
			      set usign_vsa_sort [lsort -integer $usign_vsa]	
			switch [lindex $usign_vsa_sort] {
			1 {
				binary scan [lindex $all_avp $i 2] x6c1c1c1c1 oct4 oct3 oct2 oct1
				append result_vsa "Client_DNS_Primary::$oct4.$oct3.$oct2.$oct1 "
			}
			2 {
				binary scan [lindex $all_avp $i 2] x6c1c1c1c1 oct4 oct3 oct2 oct1
				append result_vsa "Client_DNS_Second::$oct4.$oct3.$oct2.$oct1 "
			}
			4 {
				binary scan [lindex $all_avp $i 2] x6a* vsa4_value
				append result_vsa "Context_Name::$vsa4_value "
			}
			38 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa38_value
                                  if {$vsa38_value == 11} {
                                  set vsa38 "DSL"
                                  } else {
			              append result_vsa "Medium_Type::$vsa38_value "
                                      }
				append result_vsa "Medium_Type::$vsa38 "
			}
			62 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa62_value
				append result_vsa "NAS_real_port::$vsa62_value "
			}
			87 {
				binary scan [lindex $all_avp $i 2] x6a* Qos_Policing_Profile_Name
				append result_vsa "Qos_Policing_Profile_Name::$Qos_Policing_Profile_Name "
			}
			88 {
				binary scan [lindex $all_avp $i 2] x6a* Qos_Metering_Profile_Name
				append result_vsa "Qos_Metering_Profile_Name::$Qos_Metering_Profile_Name "
			}
			98 {
				binary scan [lindex $all_avp $i 2] x6I1 vsa98_value
                                  if {$vsa98_value == 2} {
                                  set vsa98 "SmartEdge-800"
                                  } else {
			              append result_vsa "Medium_Type::$vsa98_value "
                                      }
				append result_vsa "Platform_Type::$vsa98 "
			}
			112 {
				binary scan [lindex $all_avp $i 2] x6a* vsa112_value
				append result_vsa "OS_Version::$vsa112_value "
			}
			113 {
				binary scan [lindex $all_avp $i 2] x6a* Session_Traffic_Limit
				append result_vsa "Session_Traffic_Limit::$Session_Traffic_Limit "
			}
			145 {
				binary scan [lindex $all_avp $i 2] x6a* vsa145_value
				append result_vsa "MAC_Addr::$vsa145_value "
			}
			190 {
				binary scan [lindex $all_avp $i 2] x6a* Service_Name
				append result_vsa "Service Name::$Service_Name "
			}
			196 {
				binary scan [lindex $all_avp $i 2] x6a* Dynamic_QoS_Param
				append result_vsa "Dynamic_QoS_Param::$Dynamic_QoS_Param "
			}
			207 {
				binary scan [lindex $all_avp $i 2] x6a* rb_ipv6_dns
				append result_vsa "RB_IPv6_DNS::$rb_ipv6_dns "
			}
			208 {
				binary scan [lindex $all_avp $i 2] x6a* rb_ipv6
				append result_vsa "RB_IPv6_Option::$rb_ipv6 "
			}
			212 {
				binary scan [lindex $all_avp $i 2] x6I1 delegated_max_prefix
				append result_vsa "Delegated_Max_Prefix::$delegated_max_prefix "
			}
			default {
				append result_vsa "Value not in list cut:[lindex $all_avp $i 2] "
			}
		  }
		 
	   } else {
			switch [lindex $all_avp $i 0] {
            1 {
				 binary scan [lindex $all_avp $i 2] A* username
			 append result_vsa "User::$username "
			   }
            2 {
				 binary scan [lindex $all_avp $i 2] H* password
			 append result_vsa "Password::$password "
			   }
            4 {
				 binary scan [lindex $all_avp $i 2] A* nas_ip
			 append result_vsa "NAS_IP::$nas_ip "
			   }
            5 {
				 binary scan [lindex $all_avp $i 2] A* nas_port
			 append result_vsa "NAS_Port::$nas_port "
			   }

            6 {
				 binary scan [lindex $all_avp $i 2] A* service_type
                                  if {$service_type == 2} {
                                  set serv_type "Frame"
                                  } else {
			              append result_vsa "Service_Type::$service_type "
                                      }
			 append result_vsa "Service_Type::$serv_type "
			   }
            7 {
				 binary scan [lindex $all_avp $i 2] A* frame_proto
                                  if {$frame_proto == 1} {
                                  set frame_pt "PPP"
                                  } else {
			              append result_vsa "Framed_Protocol::$frame_proto "
                                      }
			 append result_vsa "Framed_Protocol::$frame_pt "
			   }
            8 {
				 binary scan [lindex $all_avp $i 2] A* frame_ip
			 append result_vsa "IP_Address::$frame_ip "
			   }
            9 {
				 binary scan [lindex $all_avp $i 2] A* frame_netmask
			 append result_vsa "Netmask::$frame_netmask "
			   }
			25 {
				 binary scan [lindex $all_avp $i 2] H* Class
			 append result_vsa "Class::$Class "
			   }
			27 {
				 binary scan [lindex $all_avp $i 2] A* sess_timeout
			 append result_vsa "Session_Timeout::$sess_timeout "
			   }
			31 {
			 binary scan [lindex $all_avp $i 2] A* cs_id
			 append result_vsa "Calling_Staion_ID::$cs_id "
			   }
			32 {
			 binary scan [lindex $all_avp $i 2] A* nas_iden
			 append result_vsa "NAS_Identifier::$nas_iden "
			   }
			40 {
			 binary scan [lindex $all_avp $i 2] A* Acct_status
			 append result_vsa ""
			   }
			41 {
			 binary scan [lindex $all_avp $i 2] I1 Acct_Delay_Time
			 append result_vsa "Delay_Time::$Acct_Delay_Time "
			   }
			44 {
			 binary scan [lindex $all_avp $i 2] A* Acct_session_id
			 append result_vsa "Acct_Session_ID:$Acct_session_id "
			   }
			45 {
				 binary scan [lindex $all_avp $i 2] I1 acct_authentic
                                  if {$acct_authentic == 1} {
                                  set acc_authen "Radius"
                                  } else {
			              append result_vsa "Acct_Authentic::$acct_authentic "
                                      }
                                  append result_vsa "Acct_Authentic::$acc_authen "
			   }
			55 {
				 binary scan [lindex $all_avp $i 2] I* Event_Timestamp
				 set systemTime [clock format $Event_Timestamp -format {%b %d, %Y %H:%M:%S }]
				 append result_vsa "Time::$systemTime"
			   }
			61 {
				 binary scan [lindex $all_avp $i 2] A* nas_port_ty
                                  if {$nas_port_ty == 5} {
                                  set nas_port_type "Virtual"
                                  } else {
			              append result_vsa "NAS_Port_Type::$nas_port_ty "
                                      }
                                  append result_vsa "NAS_Port_Type::$nas_port_type "
			   }
			85 {
				 binary scan [lindex $all_avp $i 2] I1 Acct_Interim_Interval
			 append result_vsa "Acct_Interim_Interval::$Acct_Interim_Interval "
			   }
			87 {
				 binary scan [lindex $all_avp $i 2] A* nas_port_id
			 append result_vsa "NAS_Port_ID::$nas_port_id "
			   }
			96 {
				 binary scan [lindex $all_avp $i 2] H* Framed_Interface_Id
			 append result_vsa "Interface_ID::$Framed_Interface_Id "
			   }
			97 {
				 binary scan [lindex $all_avp $i 2] x1c1H4H4H4H4H4H4H4H4 IPv6_Prefix 1st 2nd 3rd 4th 5th 6th 7th 8th
			 append result_vsa "IPv6::$1st:$2nd:$3rd:$4th:$5th:$6th:$7th:$8th/$IPv6_Prefix "
			   }
			default {
			 append result_vsa "[lindex $all_avp $i 2] "
				} 
			 }
		  }
 }
  log "$result_vsa"
}