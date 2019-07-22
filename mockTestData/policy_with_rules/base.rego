package main


#warn[msg] {
#  input.weather == "bad"
#  msg = "I don't like bad weather"
#}

# warn[msg] {
#   true
#   msg = sprintf("INPUT: \n %s", [input]) 
# }

warn[msg] {
  input.name == "service"
  input.weather == "bad"
  msg = "Found name 'service' and weather 'bad'"
}