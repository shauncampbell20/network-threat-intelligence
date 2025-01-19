# Clear Working Directory
rm(list=ls())
setwd(dirname(rstudioapi::getSourceEditorContext()$path))

# Load httr library
library("httr")

# Read and append the different data sources
## Keep only one instance of each unique ASN number
data = read.csv(file.path('./data', "historical.csv"))
src_ips <- unique(data$src_ip)
data = read.csv(file.path('./data',"20230728.csv"))
src_ips <- c(src_ips, unique(data$srcip))
data = read.csv(file.path('./data',"20231127.csv"))
src_ips <- c(src_ips, unique(data$srcip))
src_ips <- unique(src_ips)

# Set API endpoint
endpoint <- "https://api.bgpview.io/asn/"

# Create list to store responses
d = list()
# Loop through each ASN
# GET request to API url
# parse out the response data and store in d
# Sleep to avoid any rate limits
for (i in seq(from = 1, to = length(src_ips), by = 1)) {
  url <- paste(endpoint, src_ips[i], sep='')
  r <- GET(url)
  response <- content(r, as = "parsed")$data
  dat <- c(
    asn = src_ips[i],
    name = ifelse(is.null(response$name), '', response$name),
    description = ifelse(is.null(response$description_short), '', response$description_short),
    country_code = ifelse(is.null(response$country_code), '', response$country_code),
    traffic_estimation = ifelse(is.null(response$traffic_estimation), '', response$traffic_estimation),
    traffic_ratio = ifelse(is.null(response$traffic_ratio), '', response$traffic_ratio),
    rir_country_code = ifelse(is.null(response$rir_allocation$country_code), '', response$rir_allocation$country_code),
    rir_date_allocated = ifelse(is.null(response$rir_allocation$date_allocated), '', response$rir_allocation$date_allocated)
  )
  d[[i]] <- dat
  cat(i/length(src_ips), end='/r')
  Sys.sleep(.5)
}

# Convert results list to dataframe
# Convert date allocated to date type
# Write dataframe to csv
final = as.data.frame(do.call("rbind",d))
final$rir_date_allocated <- as.Date(final$rir_date_allocated, format = "%Y-%m-%d %H:%M:%S")
write.csv(final, file.path('./data', 'asn.csv'), row.names = FALSE)
