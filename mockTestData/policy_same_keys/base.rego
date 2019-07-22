package main


warn[msg] {
  input.weather.weather == "bad"
  `input.weather-good.weather` == "good"
  msg = "I don't like bad weather"
}
#we're going to use file names and paths to namespaces thing