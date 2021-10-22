from datetime import datetime as dt
from mydig import mydig_resolver
import dns.resolver
import numpy as np
import matplotlib.pyplot as plt

NUM_ITERATIONS = 10
#multi_pass_websites = ['Google.co.jp', 'Google.de','Google.co.uk','Google.co.br','Google.co.in']
website_list = ['Google.com', 'Youtube.com', 'Tmall.com', 'Twitter.com', 'Weibo.com', 'Ebay.com', 'Facebook.com', 'Taobao.com', 'Linkedin.com',
    'Gmail.com', 'Amazon.com', 'Yahoo.com', 'Wikipedia.org', 'Bing.com', 'Outlook.com', 'Zoom.us', 'Twitch.tv', 'Live.com',
    'Netflix.com', 'Reddit.com', 'Microsoft.com','Instagram.com', 'Office.com', 'Google.com.hk', 'Myshopify.com']

def recursive_resolver(local_name_servers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = local_name_servers
    return resolver

def run_test(resolver, mydig = False):
    avg_time_list = []
    for website in website_list:
        time_sum = 0
        for _ in range(NUM_ITERATIONS):
            start = dt.now()
            if mydig:
                dns = resolver(website, 'A')
                print(dns)
            else:
                _ = resolver.query(website, 'A')
            # diff in msec
            tt = (dt.now() - start).total_seconds() * 1000
            time_sum += tt
        
        avg_time = time_sum / NUM_ITERATIONS
        avg_time_list.append(round(avg_time, 2))

    return avg_time_list

def draw_cdf_graph(x_mydig, y_cdf_mydig, x_local, y_cdf_local, x_google, y_cdf_google, title):
    # plot CDF
    plt.figure(title + ' CDF', figsize=(20,8))
    plt.step(x_mydig + [1.5], y_cdf_mydig + [1], where='post', lw = 2, label='MyDig CDF')
    plt.step(x_local + [1.5], y_cdf_local + [1], where='post', lw = 2, label='Local DNS (172.31.16.1) CDF')
    plt.step(x_google + [1.5], y_cdf_google + [1], where='post', lw = 2, label='Google DNS CDF')

    plt.title(title + ' CDF with %d samples.' % (len(x_mydig[1:])), fontsize=18)
    plt.xticks(np.arange(0, 2, 0.1))
    plt.yticks(np.arange(0, 1.1, 0.1))
    plt.xlabel('Avg Resolution Time (in sec)')
    plt.ylabel('CDF / Pr(X <= x)')
    plt.legend(loc='lower right')
    plt.grid()
    plt.show()

# returns the sorted list of average times and the CDF for each entry
def get_cdf(sample_list):
	num_samples = len(sample_list)

	# sort the samples in asc order
	sample_list.sort()

	# initialize the lists that will contain the values to be represented on both X and Y axes. Since the graph will start at 0, we initialize
	# the first element of both to 0. X-axis: The avg resolution time for each website, Y-axis: CDF of each website x
	x_sample = [0]
	y_cdf = [0]

	# Pr(X<=x)
	cumulative_pr = 0
	for sample_data in sample_list:
		cumulative_pr += 1 / num_samples
		x_sample.append(sample_data)
		y_cdf.append(cumulative_pr)

	return x_sample, y_cdf

# Results of running custom DNS mydig resolver
mydig_time = run_test(mydig_resolver, True)
# Using local DNS that my wifi connect to by default (172.31.16.1)
local_dns_time = run_test(recursive_resolver(['172.31.16.1']), False)
# Using Google Public DNS (8.8.8.8, 8.8.4.4)
google_dns_time = run_test(recursive_resolver(['8.8.8.8', '8.8.4.4']), False)

print("mydig_time:", mydig_time)
print("local_dns_time:", local_dns_time)
print("google_dns_time:", google_dns_time)

# Plot CDF Graphs for all 3 avg time resolutions
x_mydig, y_cdf_mydig = get_cdf(mydig_time)
x_local, y_cdf_local = get_cdf(local_dns_time)
x_google, y_cdf_google = get_cdf(google_dns_time)
draw_cdf_graph(x_mydig, y_cdf_mydig, x_local, y_cdf_local, x_google, y_cdf_google, title='Avg DNS Resolution Comparison')