### Shaun Campbell
### COSC 6510
### Final Project

# clear working directory
rm(list=ls())
setwd(dirname(rstudioapi::getSourceEditorContext()$path))

# Load required libraries
library(ggplot2)
library(dplyr)
library(data.table)
library(pROC)
library(caret)


#############################
#############################
##     DATA MANAGEMENT     ##
#############################
#############################

#######################
###   NETWORK DATA  ###
#######################

data <- read.csv(file.path('./data', "historical.csv"), row.names = 1)

# Clean up data
## Omission used because the data set is large enough
## Only  keep records where bytes were transferred in or out, otherwise it's not a network flow
## Reclassify 'outlier' label as benign because I'm only interested in predicting truly malicious traffic
## Convert protocol to factor instead of int
## Remove source port, destination port, time start, and time end since they are not of interest
## Remove entropy, total entropy, avg_ipt because they are not available in my company's network logs
data <- na.omit(data)
data <- data[which(data$bytes_in != 0 | data$bytes_out != 0),]
data$label[data$label == 'outlier'] <- 'benign'
data$proto <- as.factor(data$proto)
data <- data[, c("proto", "src_ip", "dest_ip", "bytes_in", "bytes_out", "num_pkts_out", "num_pkts_in", "duration", "label")]

# Check different levels of proto. Create indicator variables for protocol 17 and 1, with 6 as baseline
table(data[,c('proto','label')])
data$proto17 <- as.factor(ifelse(data$proto == 17, 1, 0))
data$proto1 <- as.factor(ifelse(data$proto == 1, 1, 0))

# Check summary statistics of the numeric variables
summary(data[, c('bytes_in', 'bytes_out','num_pkts_out','num_pkts_in','duration')])

# Create histograms to assess distributions of the variables
## All the variables are highly skewed left
par(mfrow=c(2,3))
hist(data$bytes_in, xlab = '', main = 'Bytes In')
hist(data$bytes_out, xlab = '', main = 'Bytes Out')
hist(data$num_pkts_out, xlab = '', main = 'Packets Out')
hist(data$num_pkts_in, xlab = '', main = 'Packets In')
hist(data$duration, xlab = '', main = 'Duration')

# All the variables are highly skewed left, and contain 0 values, so apply log(x+1) transformations
data$log_bytes_in = log(data$bytes_in+1)
data$log_bytes_out = log(data$bytes_out+1)
data$log_num_pkts_out = log(data$num_pkts_out+1)
data$log_num_pkts_in = log(data$num_pkts_in+1)
data$log_duration = log(data$duration+1)

# Re-plot the histograms
## several variables are still skewed but in general the distributions look much better
par(mfrow=c(2,3))
hist(data$log_bytes_in, xlab = '', main = "Log Bytes In")
hist(data$log_bytes_out, xlab = '', main = "Log Bytes Out")
hist(data$log_num_pkts_out, xlab = '', main = "Log Packets In")
hist(data$log_num_pkts_in, xlab = '', main = "Log Packets Out")
hist(data$log_duration, xlab = '', main = "Log Duration")

# Boxplots to check outliers
par(mfrow=c(2,3))
boxplot(data$log_bytes_in, main='Log Bytes In')
boxplot(data$log_bytes_out, main='Log Bytes Out')
boxplot(data$log_num_pkts_out, main='Log Packets Out')
boxplot(data$log_num_pkts_in, main='Log Packets In')
boxplot(data$log_duration, main='Log Duration')

# Reset plot space
par(mfrow=c(1,1))

# See the number of outliers for each variable
## Too many outliers to remove, so they are retained
length(boxplot.stats(data$log_bytes_in)$out)
length(boxplot.stats(data$log_bytes_out)$out)
length(boxplot.stats(data$log_num_pkts_out)$out)
length(boxplot.stats(data$log_num_pkts_in)$out)
length(boxplot.stats(data$log_duration)$out)

# Create integer indicator variable y for label
# Create indicator variable yf to be used as factor later
data$y = ifelse(data$label == 'malicious', 1, 0)
data$yf = as.factor(data$y)


#######################
###     ASN DATA    ###
#######################

# Read ASN data and regions information
## Convert rir_date_allocated to date
## Merge regions with ASN data
## Drop rows with blank country code or region
## Remove any duplicate rows
asn <- read.csv(file.path('./data', "asn.csv"))
regions = read.csv(file.path('./data', "regions.csv"))
asn$rir_date_allocated <- as.Date(asn$rir_date_allocated, format = "%Y-%m-%d")
asn <- merge(asn, regions, by.x = "country_code", by.y = "Country.Code", all.x = TRUE)
asn <- asn[which(asn$country_code != ""),]
asn <- asn[!is.na(asn$Region), ]
asn <- asn[!duplicated(asn$asn),]

# Create new variable "age" for days since the ASN was assigned
asn$age <- as.Date('2023-11-11') - asn$rir_date_allocated

# Merge with network data and remove any rows where region is na
data$id <- 1:nrow(data)
df <- merge(data, asn, by.x = "src_ip", by.y = "asn", all.x = TRUE)
df <- df[!is.na(df$Region), ]

## The data merges in a different order when read from a csv 
## versus when it's sampled directly into a dataframe from the folder trees.
## To ensure the numbers are the same I order it in the same way the original data
## was ordered because it's randomly sampled with a set seed later.
rowids <- read.csv(file.path('./data', 'rowids.csv'))
df <- merge(df, rowids, by.x = 'id', by.y = 'id')
df <- df[order(df$X),]
rownames(df) <- 1:nrow(df)

# Fill missing age values with mean and convert to integer
meanAge <- mean(na.omit(df$age))
df[is.na(df$age),'age'] <- meanAge
df$age <- as.integer(df$age)

# 17 distinct regions, so make 16 indicator variables. Northern America used as baseline. 
## Combine Melanesia, Micronesia, and Polynesia into "other" resulting in 14 indicators
df$Australia_and_New_Zealand <- ifelse(df$Region == "Australia and New Zealand", 1, 0)
df$Central_Asia <- ifelse(df$Region == "Central Asia", 1, 0)
df$Eastern_Asia <- ifelse(df$Region == "Eastern Asia", 1, 0)
df$Eastern_Europe <- ifelse(df$Region == "Eastern Europe", 1, 0)
df$Latin_America_and_the_Caribbean <- ifelse(df$Region == "Latin America and the Caribbean", 1, 0)
df$Northern_Africa <- ifelse(df$Region == "Northern Africa", 1, 0)
df$Northern_Europe <- ifelse(df$Region == "Northern Europe", 1, 0)
df$Other <- ifelse(df$Region %in% c("Polynesia", "Melanesia","Micronesia"), 1, 0)
df$South_eastern_Asia <- ifelse(df$Region == "South-eastern Asia", 1, 0)
df$Southern_Asia <- ifelse(df$Region == "Southern Asia", 1, 0)
df$Southern_Europe <- ifelse(df$Region == "Southern Europe", 1, 0)
df$Sub_Saharan_Africa <- ifelse(df$Region == "Sub-Saharan Africa", 1, 0)
df$Western_Asia <- ifelse(df$Region == "Western Asia", 1, 0)
df$Western_Europe <- ifelse(df$Region == "Western Europe", 1, 0)

# Most common traffic level is 500-1000Gbps so replace missing values with that
## Create indicator variables for traffic levels, using 500-1000Gbps as baseline
sort(table(df$traffic_estimation), decreasing = TRUE)
df[which(df$traffic_estimation == ""),'traffic_estimation'] <- "500-1000Gbps"
u <- unique(asn$traffic_estimation)
u <- u[!u %in% c("","500-1000Gbps")]
for (c in u) {
  df[,c] <- ifelse(df$traffic_estimation == c, 1, 0)
}

# Most common traffic ratio is Mostly Inbound so replace missing values with that
## Create indicator variables for traffic ratio, using mostly inbound as baseline
sort(table(df$traffic_ratio), decreasing = TRUE)
df[which(df$traffic_ratio == ""),'traffic_ratio'] <- "Mostly Inbound"
u <- unique(asn$traffic_ratio)
u <- u[!u %in% c("","Mostly Inbound")]
for (c in u) {
  df[,c] <- ifelse(df$traffic_ratio == c, 1, 0)
}

# Set seed for reproducible results. Reserve 25% of data for test data to avoid snooping.
set.seed(123)
sampleSize <- floor(nrow(df)*.75)
trainInd <- sample(seq_len(nrow(df)), size = sampleSize)
test_df <- df[-trainInd,]
df <- df[trainInd,]

#############################
#############################
##           VIZ           ##
#############################
#############################

## WARNING: Some plots take a while to generate.

# Boxplot to see distribution of the independent variables between malicious and benign traffic
ggplot(data = df) + 
  geom_boxplot(mapping = aes(y = log_bytes_in, x = 'Bytes In', fill=label, color=label), outlier.alpha = 0.1, alpha=.3, outlier.size = 1) + 
  geom_boxplot(mapping = aes(y = log_bytes_out, x = 'Bytes Out', fill=label, color=label), outlier.alpha = 0.1, alpha=.3, outlier.size = 1) + 
  geom_boxplot(mapping = aes(y = log_num_pkts_in, x = 'Packets In', fill=label, color=label), outlier.alpha = 0.1, alpha=.3, outlier.size = 1) + 
  geom_boxplot(mapping = aes(y = log_num_pkts_out, x = 'Packets Out', fill=label, color=label), outlier.alpha = 0.1, alpha=.3, outlier.size = 1) + 
  geom_boxplot(mapping = aes(y = log_duration, x = 'Duration', fill=label, color=label), outlier.alpha = 0.1, alpha=.3, outlier.size = 1) + 
  labs(x = "Variable", y = "Log Value", title = "Distributions of Traffic Variables") +
  scale_fill_manual(values = c("malicious" = "red2", "benign" = "chartreuse3")) +
  scale_color_manual(values = c("malicious" = "darkred", "benign" = "darkgreen")) +
  theme(
    text = element_text(size = 30),
    plot.title = element_text(hjust = 0.6), 
  ) 
  
# Stacked bar chart - benign and malicious traffic between proto 6 and 17 and 1
ggplot(df, aes(x=proto, fill=label)) + geom_bar(position = 'fill') +
  labs(x = "Protocol", y = "Proportion", title = "Protocol 6 vs 17") +
  theme(plot.title = element_text(hjust = 0.5)) + scale_fill_manual(values = c("malicious" = "red2", "benign" = "chartreuse3"))

# Scatter plot - Packets in vs packets out
ggplot(df, aes(x=log_num_pkts_in, y = log_num_pkts_out, color=label)) + geom_point(alpha=1/5) +
  scale_color_manual(values = c("malicious" = "red2", "benign" = "green")) +
  labs(x = "Log Packets In", y = "Log Packets Out", title = "Packets In vs Packets Out") +
  theme(plot.title = element_text(hjust = 0.5)) 

# Scatter plot - Bytes in vs bytes out
ggplot(df, aes(x=log_bytes_in, y = log_bytes_out, color=label)) + geom_point(alpha=1/5) +
  scale_color_manual(values = c("malicious" = "red2", "benign" = "green")) +
  labs(x = "Log Bytes In", y = "Log Bytes Out", title = "Bytes in vs Bytes Out") +
  theme(plot.title = element_text(hjust = 0.5))

# Scatter plot - Bytes in vs packets in
ggplot(df, aes(x=log_num_pkts_in, y = log_bytes_in, color=label)) + geom_point(alpha=.05, size=3) +
  scale_color_manual(values = c("malicious" = "red2", "benign" = "green")) +
  labs(x = "Log Bytes In", y = "Log Packets In", title = "Bytes In vs Packets In") +
  guides(colour = guide_legend(override.aes = list(alpha=1))) +
  theme(text = element_text(size = 25),
        legend.position=c(.8,.2),
        plot.title = element_text(hjust = 0.5), ) 

# Scatter plot - Bytes out vs packets out
ggplot(df, aes(x=log_bytes_out, y = log_num_pkts_out, color=label)) + geom_point(alpha=1/5) +
  scale_color_manual(values = c("malicious" = "red2", "benign" = "green")) +
  labs(x = "Log Bytes Out", y = "Log Packets Out", title = "Bytes Out vs Packets Out") +
  theme(plot.title = element_text(hjust = 0.5)) 

# Bar plot -  malicious/benign by region
plt = df %>% group_by(Region) %>% summarise(malicious = sum(y), benign = length(y)-sum(y), total = length(y), ratio = sum(y)/length(y))
plt=plt[order(plt$ratio, decreasing = FALSE),]
ggplot(df, aes(x=factor(Region, level=plt$Region), fill=label, color=label)) + geom_bar(position = 'fill', alpha=.3) + 
  theme(axis.text.x = element_text(angle = 45, vjust = 1, hjust=1)) + 
  labs(x = "", y = "", title = "Proportion of Traffic Type by Region") +
  theme(plot.title = element_text(hjust = 0.5),
        text = element_text(size = 30))  + 
  scale_fill_manual(values = c("malicious" = "red2", "benign" = "chartreuse3")) +
  scale_color_manual(values = c("malicious" = "darkred", "benign" = "darkgreen")) 

# Bar plot - malicious/benign by traffic estimation
plt = df %>% group_by(traffic_estimation) %>% summarise(malicious = sum(y), benign = length(y)-sum(y), total = length(y), ratio = sum(y)/length(y))
plt=plt[order(plt$ratio, decreasing = FALSE),]
ggplot(df, aes(x=factor(traffic_estimation, level=plt$traffic_estimation), fill=label)) + geom_bar(position = 'fill') + 
  theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1)) +
  labs(x = "", y = "", title = "Proportion of Traffic Type by Traffic Estimation") +
  theme(plot.title = element_text(hjust = 0.5))  + 
  scale_fill_manual(values = c("malicious" = "red2", "benign" = "palegreen"))

# Bar plot - malicious/benign by traffic ratio
plt = df %>% group_by(traffic_ratio) %>% summarise(malicious = sum(y), benign = length(y)-sum(y), total = length(y), ratio = sum(y)/length(y))
plt=plt[order(plt$ratio, decreasing = FALSE),]
ggplot(df, aes(x=factor(traffic_ratio, level=plt$traffic_ratio), fill=label)) + geom_bar(position = 'fill') + 
  theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1)) +
  labs(x = "", y = "", title = "Proportion of Traffic Type by Traffic Ratio") +
  theme(plot.title = element_text(hjust = 0.5))  + 
  scale_fill_manual(values = c("malicious" = "red2", "benign" = "palegreen"))

# Bar plot - malicious/benign by description
plt = df %>% group_by(description) %>% summarise(malicious = sum(y), benign = length(y)-sum(y), total = length(y), ratio = sum(y)/length(y))
plt = plt[order(plt$total, decreasing = TRUE),][1:20,]
ggplot(na.omit(plt), aes(x = reorder(description, ratio), y = ratio)) + 
  geom_bar(position='stack', stat='identity') + 
  theme(axis.text.x = element_text(angle = 45, vjust = 1, hjust=1)) +
  labs(x = "", y = "", title = "Proportion of Traffic Type by ASN Description") +
  theme(plot.title = element_text(hjust = 0.5)) 

#############################
#############################
##       PROBABILITY       ##
#############################
#############################

# Overall likelihood of malicious traffic
length(which(df$label == 'malicious'))/nrow(df)

#likelihood of malicious if log_bytes_in between 5 and 6
plot(density(df[which(df$label == 'malicious'), ]$log_bytes_in), col='red', main='Log Bytes In')
lines(density(df[which(df$label == 'benign'), ]$log_bytes_in), col='green')
legend(9, .75, legend=c("Malicious", "Benign"),  fill = c("red","green"))
range1 = 5; range2 = 6
pB = length(which(df$log_bytes_in >= range1 & df$log_bytes_in <= range2 ))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$log_bytes_in >= range1 & df$log_bytes_in <= range2))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given log_bytes_in is between', range1, 'and', range2)

#likelihood of malicious if log_bytes_out between 5 and 5.5
plot(density(df[which(df$label == 'malicious'), ]$log_bytes_out), col='red', main='Log Bytes Out')
lines(density(df[which(df$label == 'benign'), ]$log_bytes_out), col='green')
legend(9, 1.5, legend=c("Malicious", "Benign"),  fill = c("red","green"))
range1 = 5; range2 = 5.5
pB = length(which(df$log_bytes_out >= range1 & df$log_bytes_out <= range2))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$log_bytes_out >= range1 & df$log_bytes_out <= range2))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given log_bytes_out is between', range1, 'and', range2)

#likelihood of malicious if log_num_pkts_out between 1.75 and 2.25
plot(density(df[which(df$label == 'malicious'), ]$log_num_pkts_out), col='red', main='Log Num Pkts Out')
lines(density(df[which(df$label == 'benign'), ]$log_num_pkts_out), col='green')
legend(4.5, 1.5, legend=c("Malicious", "Benign"),  fill = c("red","green"))
range1 = 1.75; range2 = 2.25
pB = length(which(df$log_num_pkts_out >= range1 & df$log_num_pkts_out <= range2))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$log_num_pkts_out >= range1 & df$log_num_pkts_out <= range2))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given log_num_pkts_out is between', range1, 'and', range2)

#likelihood of malicious if log_num_pkts_in between 1.75 and 2.25
plot(density(df[which(df$label == 'malicious'), ]$log_num_pkts_in), col='red', main='Log Num Pkts In')
lines(density(df[which(df$label == 'benign'), ]$log_num_pkts_in), col='green')
legend(4.5, 1.5, legend=c("Malicious", "Benign"),  fill = c("red","green"))
range1 = 1.75; range2 = 2.25
pB = length(which(df$log_num_pkts_in >= range1 & df$log_num_pkts_in <= range2))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$log_num_pkts_in >= range1 & df$log_num_pkts_in <= range2))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given log_num_pkts_in is between', range1, 'and', range2)

#likelihood of malicious if log duration between 0 and 0.5
plot(density(df[which(df$label == 'benign'), ]$log_duration), col='green', main='Log Duration')
lines(density(df[which(df$label == 'malicious'), ]$log_duration), col='red')
legend(3, 20, legend=c("Malicious", "Benign"),  fill = c("red","green"))
range1 = 0; range2 = 0.5
pB = length(which(df$log_duration >= range1 & df$log_duration <= range2))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$log_duration >= range1 & df$log_duration <= range2))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given log_duration is between', range1, 'and', range2)

#Likelihoods of malicious given each region
for (r in unique(df$Region)) {
  pB = length(which(df$Region == r))/nrow(df)
  pAiB = length(which(df$label=='malicious' & df$Region == r))/nrow(df)
  cat(round(pAiB/pB*100,2),'% chance of malicious given region is', r, '\n')
}

#Likelihoods of malicious given each traffic estimation
for (r in unique(df$traffic_estimation)) {
  pB = length(which(df$traffic_estimation == r))/nrow(df)
  pAiB = length(which(df$label=='malicious' & df$traffic_estimation == r))/nrow(df)
  cat(round(pAiB/pB*100,2),'% chance of malicious given traffic_estimation is', r, '\n')
}

#Likelihoods of malicious given each traffic ratio
for (r in unique(df$traffic_ratio)) {
  pB = length(which(df$traffic_ratio == r))/nrow(df)
  pAiB = length(which(df$label=='malicious' & df$traffic_ratio == r))/nrow(df)
  cat(round(pAiB/pB*100,2),'% chance of malicious given traffic_ratio is', r, '\n')
}

#likelihood of malicious if age of ASN is less than 10000 days
plot(density(df[which(df$label == 'benign'), ]$age), col='green', main = 'ASN Age')
lines(density(df[which(df$label == 'malicious'), ]$age), col='red')
legend(0, .0015, legend=c("Malicious", "Benign"),  fill = c("red","green") )
pB = length(which(df$age < 10000))/nrow(df)
pAiB = length(which(df$label=='malicious' & df$age < 10000))/nrow(df)
cat(round(pAiB/pB*100,2),'% chance of malicious given age is less than 10000')

#############################
#############################
##  STATISTICAL INFERENCE  ##
#############################
#############################

# Create matrix to store t-test results
m <- matrix(nrow = 6, ncol = 9)
colnames(m) <- c("Variable","Benign Mean", "Malicious Mean", "t", "p", "95% CI, lower", "95% CI, upper","df", "se")

# T-test for difference in mean bytes in between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$log_bytes_in
g2 = df[which(df$label == 'malicious'), ]$log_bytes_in
t <- t.test(g1, g2, var.equal = TRUE)
m[1,] <- c('log_bytes_in', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# T-test for difference in mean bytes out between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$log_bytes_out
g2 = df[which(df$label == 'malicious'), ]$log_bytes_out
t <- t.test(g1, g2, var.equal = TRUE)
m[2,] <- c('log_bytes_out', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# T-test for difference in mean packets in between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$log_num_pkts_in
g2 = df[which(df$label == 'malicious'), ]$log_num_pkts_in
t <- t.test(g1, g2, var.equal = TRUE)
m[3,] <- c('log_num_pkts_in', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# T-test for difference in mean packets out between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$log_num_pkts_out
g2 = df[which(df$label == 'malicious'), ]$log_num_pkts_out
t <- t.test(g1, g2, var.equal = TRUE)
m[4,] <- c('log_num_pkts_out', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# T-test for difference in mean duration between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$log_duration
g2 = df[which(df$label == 'malicious'), ]$log_duration
t <- t.test(g1, g2, var.equal = TRUE)
m[5,] <- c('log_duration', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# T-test for difference in mean age between benign and malicious. 
g1 = df[which(df$label == 'benign'), ]$age
g2 = df[which(df$label == 'malicious'), ]$age
t <- t.test(g1, g2, var.equal = TRUE)
m[6,] <- c('age', t$estimate[[1]], t$estimate[[2]], t$statistic, t$p.value, t$conf.int, t$parameter, t$stderr)

# Show results of t-tests in console
m

# Z test for difference in proportion of malicious traffic for proto 6 and 17
s1 <- sum(df[which(df$proto == 6 & df$label == "malicious"),'y'])
s2 <- sum(df[which(df$proto == 17 & df$label == "malicious"),'y'])
n1 <- nrow(df[which(df$proto == 6),])
n2 <- nrow(df[which(df$proto == 17),])
p1 <- s1/n1
p2 <- s2/n2
se <- sqrt(p1*(1-p1)/n1 + p2*(1-p2)/n2)
z <- (p1-p2)/se
pval <- 2*pnorm(abs(z), lower.tail = FALSE)
zcrit1 <- qnorm(0.025, lower.tail=TRUE)
zcrit2 <- qnorm(0.025, lower.tail=FALSE)
estimate <- p1 - p2
ci = c(estimate + zcrit1*se, estimate + zcrit2*se)

# Show results of z-test in console
c(prop6 = p1, prop17 = p2, se=se, z=z, pval=pval, ci=ci)

# Z test for difference of proportion of malicious traffic by region compared to proportion of overall sample
## Create matrix to store results
m1 <- matrix(nrow = 16, ncol = 8)
colnames(m1) <- c("Region","Region Prop", "Sample Prop", 'SE', "Z", "p", "95% CI, lower", "95% CI, upper")
row = 1
for (r in unique(df$Region)) {
  s1 <- sum(df[which(df$Region == r & df$label == "malicious"),'y'])
  s2 <- sum(df$y)
  n1 <- nrow(df[which(df$Region == r),])
  n2 <- nrow(df)
  p1 <- s1/n1
  p2 <- s2/n2
  se <- sqrt(p1*(1-p1)/n1 + p2*(1-p2)/n2)
  z <- (p1-p2)/se
  pval <- 2*pnorm(abs(z), lower.tail = FALSE)
  zcrit1 <- qnorm(0.025, lower.tail=TRUE)
  zcrit2 <- qnorm(0.025, lower.tail=FALSE)
  estimate <- p1 - p2
  ci = c(estimate + zcrit1*se, estimate + zcrit2*se)
  m1[row,] <- c(r,p1, p2, se, z, pval, ci)
  row = row + 1
}

# Show results of z-tests in console
m1

# Z test for difference of proportion of malicious traffic by traffic estimation compared to proportion of overall sample
## Create matrix to store results
m2 <- matrix(nrow = 18, ncol = 8)
colnames(m2) <- c("Traffic Estimation","Subset Prop", "Sample Prop", 'SE', "Z", "p", "95% CI, lower", "95% CI, upper")
row = 1
for (r in unique(df$traffic_estimation)) {
  s1 <- sum(df[which(df$traffic_estimation == r & df$label == "malicious"),'y'])
  s2 <- sum(df$y)
  n1 <- nrow(df[which(df$traffic_estimation == r),])
  n2 <- nrow(df)
  p1 <- s1/n1
  p2 <- s2/n2
  se <- sqrt(p1*(1-p1)/n1 + p2*(1-p2)/n2)
  z <- (p1-p2)/se
  pval <- 2*pnorm(abs(z), lower.tail = FALSE)
  zcrit1 <- qnorm(0.025, lower.tail=TRUE)
  zcrit2 <- qnorm(0.025, lower.tail=FALSE)
  estimate <- p1 - p2
  ci = c(estimate + zcrit1*se, estimate + zcrit2*se)
  m2[row,] <- c(r,p1, p2, se, z, pval, ci)
  row = row + 1
}

# Show results of z-tests in console
m2

# Z test for difference of proportion of malicious traffic by traffic ratio compared to proportion of overall sample
## Create matrix to store results
m3 <- matrix(nrow = 6, ncol = 8)
colnames(m3) <- c("Traffic Ratio","Subset Prop", "Sample Prop", 'SE', "Z", "p", "95% CI, lower", "95% CI, upper")
row = 1
for (r in unique(df$traffic_ratio)) {
  s1 <- sum(df[which(df$traffic_ratio == r & df$label == "malicious"),'y'])
  s2 <- sum(df$y)
  n1 <- nrow(df[which(df$traffic_ratio == r),])
  n2 <- nrow(df)
  p1 <- s1/n1
  p2 <- s2/n2
  se <- sqrt(p1*(1-p1)/n1 + p2*(1-p2)/n2)
  z <- (p1-p2)/se
  pval <- 2*pnorm(abs(z), lower.tail = FALSE)
  zcrit1 <- qnorm(0.025, lower.tail=TRUE)
  zcrit2 <- qnorm(0.025, lower.tail=FALSE)
  estimate <- p1 - p2
  ci = c(estimate + zcrit1*se, estimate + zcrit2*se)
  m3[row,] <- c(r,p1, p2, se, z, pval, ci)
  row = row + 1
}

# Show results of z-tests in console
m3

#############################
#############################
##    LINEAR REGRESSION    ##
#############################
#############################

# Generate pairs plot for each of the continuous variables
## sample of 10000 is used to speed up plot drawing
## Packets in/packets out, bytes out/packets out, bytes in/packets in seem to have linear-ish relationships
df1 <- sample_n(df, 10000)
cols <- character(nrow(df1))
cols[] <- "green"
cols[df1$label == 'malicious'] <- 'red'
pairs(~log_num_pkts_in + log_num_pkts_out + log_bytes_in + log_bytes_out + log_duration, data = df1, col=cols) 

# Investigate log_bytes_in and log_num_pkts_in because it's a relationship of interest
## Fit linear model to predict log_bytes_in based on log_num_pkts_in for malicious traffic
mod_a = lm(log_bytes_in ~ log_num_pkts_in, data=df[which(df$label=='malicious'),])
summary(mod_a)

# Create dataframe for malicious traffic with x, y, prediction, and residuals
y1=df[which(df$label=='malicious'),'log_bytes_in']
x1=df[which(df$label=='malicious'),]
preds1 <- predict(mod_a, x1)
test1 = data.frame(x1,y1, preds1, resid(mod_a))

## Fit linear model to predict log_bytes_in based on log_num_pkts_in for benign traffic
mod_b = lm(log_bytes_in ~ log_num_pkts_in, data=df[which(df$label=='benign'),])
summary(mod_b)

# Create dataframe for benign traffic with x, y, prediction, and residuals
y2=df[which(df$label=='benign'),'log_bytes_in']
x2=df[which(df$label=='benign'),]
preds2 <- predict(mod_b, x2)
test2 = data.frame(x2,y2, preds2, resid(mod_b))

# Scatter plot with regression fit lines
plot(test2[,c('log_num_pkts_in','log_bytes_in')], col='green', main='Bytes In ~ Packets In Linear Models', xlab='Log Packets In', ylab='Log Bytes In')
abline(mod_b, col='green', lwd=4)
points(test1[,c('log_num_pkts_in','log_bytes_in')], col='red')
abline(mod_a, col='red', lwd=4)
legend(3.5, 3, legend=c("Malicious", "Benign"),  fill = c("red","green") )

# Plot residuals against predicted value which show inconsistent variance
par(mfrow=c(1,2))
plot(test2[,c('preds2','resid.mod_b.')], main='Benign Traffic', xlab='Predicted Value', ylab='Residual')
abline(0,0)
plot(test1[,c('preds1','resid.mod_a.')], main='Malicious Traffic', xlab='Predicted Value', ylab='Residual')
abline(0,0)

# Reset plot space
par(mfrow=c(1,1))

#############################
#############################
##  LOGISTIC REGRESSION    ##
#############################
#############################

# Add level names to yf factor
levels(df$yf) <- c("benign", "malicious")

# Model 1: base network data
# Model 2: base network data with interaction term
# Model 3: base network data with interaction term and asn data

## Create matrix to store results
tab = matrix(nrow = 4, ncol = 12)
colnames(tab) <- c('Model','Description','Accuracy','AUC','TP','TN','FP','FN','Precision','Recall','Specificity','F1')
tab[1,c('Model','Description')] <- c("Model 1","base network data")#; tab[1,'Description'] <- "base network data"
tab[2,c('Model','Description')] <- c("Model 2","base network data with interaction term")
tab[3,c('Model','Description')] <- c("Model 3","base network data with interaction term and asn data")
tab[4,c('Model','Description')] <- c("Test","Test set")

# Set up for 5-fold cross validation
myControl<-trainControl(method = "cv", number = 5) 

# Model 1 perform the cross validation
mod1 <- train(yf ~ log_bytes_in + log_bytes_out + log_num_pkts_in + log_num_pkts_out + log_duration + proto17 + proto1, 
              data = df, trControl = myControl, method = "glm", family = binomial (link = logit),
              metric = "Accuracy")

# Model 1 accuracy and summary
tab[1,'Accuracy'] <- mod1$results$Accuracy; tab[1,'Accuracy']
summary(mod1)

# Model 2 perform the cross validation
mod2 <- train(yf ~ log_bytes_in*log_num_pkts_in + log_bytes_out + log_num_pkts_out + log_duration + proto17 + proto1, 
              data = df, trControl = myControl, method = "glm", family = binomial (link = logit),
              metric = "Accuracy")

# Model 2 accuracy and summary
tab[2,'Accuracy'] <- mod2$results$Accuracy; print(tab[2,'Accuracy'])
summary(mod2)

# Model 3 perform the cross validation
mod3 <- train(yf ~ log_bytes_in*log_num_pkts_in + log_bytes_out + log_num_pkts_out + log_duration + proto17 + proto1 +
                Australia_and_New_Zealand + Central_Asia + Eastern_Asia + Eastern_Europe + Latin_America_and_the_Caribbean +
                Northern_Africa + Northern_Europe + Other + South_eastern_Asia + Southern_Asia +
                Southern_Europe + Sub_Saharan_Africa + Western_Asia + Western_Europe + age +
                `20-50Gbps` + `10-20Gbps` + `5-10Gbps` + `100-200Gbps` + `50-100Gbps` + `10-20Tbps` + `1-5Gbps` + `300-500Gbps` +
                `1-5Tbps` + `100-1000Mbps` + `200-300Gbps` + `20-50Tbps` + `5-10Tbps` + `20-100Mbps` + `50-100Tbps` + `100+Tbps` + `0-20Mbps` +
                Balanced + `Not Disclosed` + `Mostly Outbound` + `Heavy Inbound` + `Heavy Outbound`, 
              data = df, trControl = myControl, method = "glm", family = binomial (link = logit),
              metric = "Accuracy")

# Model 3 accuracy and summary
tab[3,'Accuracy'] <- mod3$results$Accuracy; print(tab[3, 'Accuracy'])
summary(mod3)

# Use Model 1 to make predictions on train set and obtain additional metrics
## True positive, true negative, false positive, false negative, and AUC
pred1 <- predict(mod1, newdata = df, type="prob")$malicious
binary1 <- round(pred1)
confusion1 <- table(df$y, binary1)
tab[1,c('TP','TN','FP','FN')] <- c(confusion1[[4]], confusion1[[1]], confusion1[[3]], confusion1[[2]])
roc1 <- roc(df$y, pred1)
tab[1, 'AUC'] <- roc1$auc[[1]]

# Use Model 2 to make predictions on train set and obtain additional metrics
## True positive, true negative, false positive, false negative, and AUC
pred2 <- predict(mod2, newdata = df, type="prob")$malicious
binary2 <- round(pred2)
confusion2 <- table(df$y, binary2)
tab[2,c('TP','TN','FP','FN')] <- c(confusion2[[4]], confusion2[[1]], confusion2[[3]], confusion2[[2]])
roc2 <- roc(df$y, pred2)
tab[2, 'AUC'] <- roc2$auc[[1]]

# Use Model 3 to make predictions on train set and obtain additional metrics
## True positive, true negative, false positive, false negative, and AUC
pred3 <- predict(mod3, newdata = df, type="prob")$malicious
binary3 <- round(pred3)
confusion3 <- table(df$y, binary3)
tab[3,c('TP','TN','FP','FN')] <- c(confusion3[[4]], confusion3[[1]], confusion3[[3]], confusion3[[2]])
roc3 <- roc(df$y, pred3)
tab[3, 'AUC'] <- roc3$auc[[1]]

# Calculate metrics precision, recall, specificity, and F1 for each model
tab[,'Precision'] <- as.numeric(tab[,'TP'])/(as.numeric(tab[,'TP'])+as.numeric(tab[,'FP']))
tab[,'Recall'] <- as.numeric(tab[,'TP'])/(as.numeric(tab[,'TP'])+as.numeric(tab[,'FN']))
tab[,'Specificity'] <- as.numeric(tab[,'TN'])/(as.numeric(tab[,'TN'])+as.numeric(tab[,'FP']))
tab[,'F1'] <- 2*(as.numeric(tab[,'Precision'])*as.numeric(tab[,'Recall']))/(as.numeric(tab[,'Precision'])+as.numeric(tab[,'Recall']))

# Shows metrics for each model in console
tab

# Fit model 3 on all train data for final model
finalModel <- glm(yf ~ log_bytes_in*log_num_pkts_in + log_bytes_out + log_num_pkts_out + log_duration + proto17 + proto1 + 
                Australia_and_New_Zealand + Central_Asia + Eastern_Asia + Eastern_Europe + Latin_America_and_the_Caribbean +
                Northern_Africa + Northern_Europe + Other + South_eastern_Asia + Southern_Asia +
                Southern_Europe + Sub_Saharan_Africa + Western_Asia + Western_Europe + age +
                `20-50Gbps` + `10-20Gbps` + `5-10Gbps` + `100-200Gbps` + `50-100Gbps` + `10-20Tbps` + `1-5Gbps` + `300-500Gbps` +
                `1-5Tbps` + `100-1000Mbps` + `200-300Gbps` + `20-50Tbps` + `5-10Tbps` + `20-100Mbps` + `50-100Tbps` + `100+Tbps` + `0-20Mbps` +
                Balanced + `Not Disclosed` + `Mostly Outbound` + `Heavy Inbound` + `Heavy Outbound`, 
              family = binomial(link = logit), data = df)

# Summary of final model
summary(finalModel)

# Confusion matrix for train set
confusionTrain <- table(df$y, binary3)
confusionTrain <- as.data.frame(confusionTrain)
ggplot(confusionTrain, aes(x=Var1, y=binary3, fill=Freq)) + geom_tile() +
  geom_text(aes(label=Freq)) +
  labs(x = "True",y = "Prediction", title = "Confusion Matrix, Train Set") + 
  scale_fill_gradient(low="white", high="purple") +
  scale_x_discrete(labels=c("Benign","Malicious")) +
  scale_y_discrete(labels=c("Benign","Malicious")) +
  theme(plot.title = element_text(hjust = 0.5)) 

# Evaluate model on test set
predTest <- predict(finalModel, newdata = test_df, type = "response")
binaryTest <- round(predTest)
tab[4,'Accuracy'] <- mean(test_df$y == binaryTest)
# Confusion matrix and TP, TN, FP, FN
confusionTest <- table(test_df$y, binaryTest)
tab[4,c('TP','TN','FP','FN')] <- c(confusionTest[[4]], confusionTest[[1]], confusionTest[[3]], confusionTest[[2]])
# ROC and AUC
rocTest <- roc(test_df$y, predTest)
tab[4, 'AUC'] <- rocTest$auc[[1]]

# Calculate metrics precision, recall, specificity, and F1 for test set
tab[4,'Precision'] <- as.numeric(tab[4,'TP'])/(as.numeric(tab[4,'TP'])+as.numeric(tab[4,'FP']))
tab[4,'Recall'] <- as.numeric(tab[4,'TP'])/(as.numeric(tab[4,'TP'])+as.numeric(tab[4,'FN']))
tab[4,'Specificity'] <- as.numeric(tab[4,'TN'])/(as.numeric(tab[4,'TN'])+as.numeric(tab[4,'FP']))
tab[4,'F1'] <- 2*(as.numeric(tab[4,'Precision'])*as.numeric(tab[4,'Recall']))/(as.numeric(tab[4,'Precision'])+as.numeric(tab[4,'Recall']))

# ROC curves for train models on train data, and model on test data
plot.roc(roc1, col = 'red', lty = "dotted",  main='ROC Curves', cex.lab=2, cex.main = 2, cex.axis=2)
plot.roc(roc2, add=TRUE, col = 'blue', lty = "dotted")
plot.roc(rocTest, col='black', add=TRUE)
plot.roc(roc3, add=TRUE, col = "green", lty="dotted")
legend(0.65, .4, legend=c("Model 1 (Train Set)", "Model 2 (Train Set)", "Model 3 (Train Set)","Model 3 (Test Set)"),  
       fill = c("red","blue","green","black"), lty = c("dotted","dotted","dotted","solid"), cex=1.4 )

# Confusion matrix for test data
confusionTest <- as.data.frame(confusionTest)
ggplot(confusionTest, aes(x=Var1, y=binaryTest, fill=Freq)) + geom_tile() +
  geom_text(aes(label=Freq), size=10, color = c('white','black','black','black')) +
  labs(x = "True Label",y = "Predicted Label", title = "Confusion Matrix for Test Set") + 
  scale_fill_gradient(low="lightblue", high="darkblue") +
  scale_x_discrete(labels=c("0","1")) +
  scale_y_discrete(labels=c("0","1")) +
  theme(plot.title = element_text(hjust = 0.5), legend.position="none",text = element_text(size = 25),
        panel.background = element_rect(fill='white'),
        panel.grid.major = element_blank(),
        panel.grid.minor = element_blank()) 

#############################
#############################
##       LIVE DATA         ##
#############################
#############################

# Create function to re-format the live data
format_live_data <- function (x) {
  # function takes a dataframe as argument for x
  # divides duration by 1000 because in train data it's in microseconds and in live data it's in milliseconds
  # Renames columns to match names in training data
  # Omits NA
  # Only keeps rows where bytes are transferred in or out
  # Merges dataframe with asn data
  # Applied log+1 transformations to numeric network variables
  # Replaces missing values for traffic estimation with 500-1000Gbps
  # Replaces missing values for traffic ratio with Mostly Inbound
  # Creates indicator variables for region, traffic estimation, and traffic ratio
  # Creates indicator variables for protocol 1 and 17
  # Replaces missing values for age with meanAge and converts age to integer
  # Returns formatted dataframe
  
  x$duration <- x$duration/1000
  
  names(x)[names(x) == 'srcip'] <- 'src_ip'
  names(x)[names(x) == 'dstip'] <- 'dest_ip'
  names(x)[names(x) == 'sentbyte'] <- 'bytes_out'
  names(x)[names(x) == 'rcvdbyte'] <- 'bytes_in'
  names(x)[names(x) == 'sentpkt'] <- 'num_pkts_out'
  names(x)[names(x) == 'rcvdpkt'] <- 'num_pkts_in'
  
  x <- na.omit(x)
  x <- x[which(x$bytes_in != 0 | x$bytes_out != 0),]
  x <- merge(x, asn, by.x = "src_ip", by.y = "asn", all.x = TRUE)
  
  x$log_bytes_in = log(x$bytes_in+1)
  x$log_bytes_out = log(x$bytes_out+1)
  x$log_num_pkts_out = log(x$num_pkts_out+1)
  x$log_num_pkts_in = log(x$num_pkts_in+1)
  x$log_duration = log(x$duration+1)
  
  x$Australia_and_New_Zealand <- ifelse(x$Region == "Australia and New Zealand", 1, 0)
  x$Central_Asia <- ifelse(x$Region == "Central Asia", 1, 0)
  x$Eastern_Asia <- ifelse(x$Region == "Eastern Asia", 1, 0)
  x$Eastern_Europe <- ifelse(x$Region == "Eastern Europe", 1, 0)
  x$Latin_America_and_the_Caribbean <- ifelse(x$Region == "Latin America and the Caribbean", 1, 0)
  x$Northern_Africa <- ifelse(x$Region == "Northern Africa", 1, 0)
  x$Northern_Europe <- ifelse(x$Region == "Northern America", 1, 0)
  x$Other <- ifelse(x$Region %in% c("Polynesia","Micronesia","Melanesia"), 1, 0)
  x$South_eastern_Asia <- ifelse(x$Region == "South-eastern Asia", 1, 0)
  x$Southern_Asia <- ifelse(x$Region == "Southern Asia", 1, 0)
  x$Southern_Europe <- ifelse(x$Region == "Southern Europe", 1, 0)
  x$Sub_Saharan_Africa <- ifelse(x$Region == "Sub-Saharan Africa", 1, 0)
  x$Western_Asia <- ifelse(x$Region == "Western Asia", 1, 0)
  x$Western_Europe <- ifelse(x$Region == "Western Europe", 1, 0)
  
  x[which(x$traffic_estimation == ""),'traffic_estimation'] <- "500-1000Gbps"
  u = unique(asn$traffic_estimation)
  u <- u[!u %in% c("","500-1000Gbps")]
  for (c in u) {
    x[,c] <- ifelse(x$traffic_estimation == c, 1, 0)
  }
  
  x[which(x$traffic_ratio == ""),'traffic_ratio'] <- "Mostly Inbound"
  u = unique(asn$traffic_ratio)
  u <- u[!u %in% c("","Mostly Inbound")]
  for (c in u) {
    x[,c] <- ifelse(x$traffic_ratio == c, 1, 0)
  }
  
  x$proto17 <- as.factor(ifelse(x$proto == 17, 1, 0))
  x$proto1 <- as.factor(ifelse(x$proto == 1, 1, 0))
  
  x[is.na(x$age),'age'] <- meanAge
  x$age <- as.integer(x$age)
  
  return (x)
}

# Read live data for Day 1 and reformat
live1 <- read.csv(file.path('./data', "20230728.csv"))
live1 <- format_live_data(live1)

# Use finalModel to classify traffic for Day 1
pred1 <- predict(finalModel, newdata = live1, type = "response")
binary1 <- round(pred1)
live1$pred <- binary1
cat(sum(binary1),'malicious instances on Day 1')

# Read live data for Day 2 and reformat
live2 <- read.csv(file.path('./data', "20231127.csv"))
live2 <- format_live_data(live2)

# Use finalModel to classify traffic for Day 2
pred2 <- predict(finalModel, newdata = live2, type = "response")
binary2 <- round(pred2)
live2$pred <- binary2
cat(sum(binary2),'malicious instances on Day 2')

# Combined malicious records into one dataframe
groupCols = c('description','Country','src_ip','Region','traffic_estimation','traffic_ratio','pred')
mal <- rbind(live1[which(live1$pred == 1), groupCols], live2[which(live2$pred == 1), groupCols])

# Summary dataframe for malicious instances across both days
mal1 <- mal[, groupCols] %>%
  group_by(description,Country,src_ip,Region,traffic_estimation,traffic_ratio) %>%
  summarise(day1 = sum(pred))
mal1

# About half of Taboola traffic is being classified as malicious
table(live1[which(live1$src_ip == 200478),'pred']) + table(live2[which(live2$src_ip == 200478),'pred'])

# Z-test for difference in proportion of malicious traffic between Day 1 and Day 2
s1 <- sum(binary1)
s2 <- sum(binary2)
n1 <- nrow(live1)
n2 <- nrow(live2)
p1 <- s1/n1
p2 <- s2/n2
se <- sqrt(p1*(1-p1)/n1 + p2*(1-p2)/n2)
z <- (p1-p2)/se
pval <- 2*pnorm(abs(z), lower.tail = FALSE)
zcrit1 <- qnorm(0.025, lower.tail=TRUE)
zcrit2 <- qnorm(0.025, lower.tail=FALSE)
estimate <- p1 - p2
ci = c(estimate + zcrit1*se, estimate + zcrit2*se)

# Show results of z-test in console
c(day1 = p1, day2 = p2, se=se, z=z, pval=pval, ci=ci)


#############################
##      ~ ~ FIN ~ ~        ##
#############################