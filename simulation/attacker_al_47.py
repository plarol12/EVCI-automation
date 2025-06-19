import networkx as nx
from collections import deque
from candidate import Candidate
from path import Path
from vulnerability import Vulnerability
import matplotlib.pyplot as plt
import sys
import copy


# Function to retrieve vulnerability data
def get_vulnerability_data():
    return [
        Vulnerability("CVE-2021-22820", "CS3", 0.002, 0.56),
        Vulnerability("CVE-2021-22730", "CS3", 0.002, 0.56),
        Vulnerability("CVE-2021-22822", "CS3", 0.001, 0.1),
        Vulnerability("CVE-2021-22723", "CS3", 0.001, 0.1),
        Vulnerability("CVE-2021-22727", "CS3", 0.002, 0.56),
        Vulnerability("CVE-2021-22707", "CS3", 0.3, 0.56),
        Vulnerability("CVE-2018-7778", "CS1", 0.004, 0.56),
        Vulnerability("CVE-2021-22725", "CS1", 0.001, 0.22),
        Vulnerability("CVE-2018-7801", "CS1", 0.02, 0.22),
        Vulnerability("CVE-2021-22821", "CS1", 0.001, 0.22),
        Vulnerability("CVE-2021-22726", "CS1", 0.001, 0.22),
        Vulnerability("CVE-2021-22708", "CS3", 0.001, 0.22),
        Vulnerability("CVE-2021-22818", "CS3", 0.002, 0.22),
        Vulnerability("CVE-2021-22820", "CS2", 0.002, 0.56),
        Vulnerability("CVE-2021-22730", "CS3", 0.002, 0.56),
        Vulnerability("CVE-2021-22727", "CS2", 0.002, 0.56),
        Vulnerability("CVE-2021-22707", "CS2", 0.3, 0.56),
        Vulnerability("CVE-2021-22774", "CS2", 0.001, 0.22),
        Vulnerability("CVE-2021-22773", "CS2", 0.001, 0.1),
        Vulnerability("CVE-2021-22822", "CS2", 0.001, 0.1),
        Vulnerability("CVE-2021-22723", "CS3", 0.001, 0.1),
        Vulnerability("CVE-2021-22721", "CS3", 0.001, 0.1),
        Vulnerability("CVE-2018-7800" , "CS3", 0.003, 0.56),
        Vulnerability("CVE-2018-16671", "CS2", 0.001, 0.1),
        Vulnerability("CVE-2018-16670", "CS2", 0.001, 0.1),
        Vulnerability("CVE-2018-16668", "CS2", 0.002, 0.1),
        Vulnerability("CVE-2022-22808", "LMS", 0.001, 0.22),
        Vulnerability("CVE-2022-22807", "LMS", 0.001, 0.22),
        Vulnerability("CVE-2018-12634", "CSC", 0.96, 0.56),
        Vulnerability("CVE-2018-17922", "CSC", 0.02, 0.56),
        Vulnerability("CVE-2018-17918", "CSC", 0.002, 0.56),
        Vulnerability("CVE-2024-25999", "CSC", 0.001, 0.22),
        Vulnerability("CVE-2018-16672", "CSC", 0.001, 0.1),
        Vulnerability("CVE-2021-34591", "CSC", 0.001, 0.56),
        Vulnerability("CVE-2016-5809", "PM1", 0.002, 0.22),
        Vulnerability("CVE-2016-5809", "PM2", 0.002, 0.22),
        Vulnerability("CVE-2017-12718", "GW", 0.3, 0.56),
        Vulnerability("CVE-2018-16669", "CSMS", 0.04, 0.56),
        Vulnerability("CVE-2023-52096", "CSMS", 0.001, 0.22),
        Vulnerability("CVE-2023-49958", "CSMS", 0.001, 0.22),
        Vulnerability("CVE-2023-49957", "CSMS", 0.001, 0.22),
        Vulnerability("CVE-2023-49956", "CSMS", 0.001, 0.22),
        Vulnerability("CVE-2023-49955", "CSMS", 0.001, 0.22),
        Vulnerability("CVE-2012-1990", "RTS", 0.56, 0.1),
        Vulnerability("CVE-2020-15912", "EV1", 0.2, 0.1),
        Vulnerability("CVE-2020-15912", "EV2", 0.2, 0.1),
        Vulnerability("CVE-2016-2278", "AS", 0.02, 0.22),
        Vulnerability("CVE-2022-0878", "EVSE1", 0.001, 0.1),
        Vulnerability("CVE-2022-0878", "EVSE2", 0.001, 0.1),
        Vulnerability("CVE-2024-20465", "SW1", 0.001, 0.22),
        Vulnerability("CVE-2018-0255", "SW2", 0.001, 0.56),
        Vulnerability("CVE-2018-0172", "SW3", 0.015, 0.56),
        Vulnerability("CVE-2018-0161", "SW2", 0.004, 0.22),
        Vulnerability("CVE-2018-0156 ", "SW3", 0.007, 0.22),
        Vulnerability("CVE-2018-0156 ", "SW1", 0.007, 0.22),
        
    ]
patches = {"CVE-2021-22820", "CVE-2021-22730", "CVE-2021-22727",
           "CVE-2021-22707", "CVE-2021-22725", "CVE-2022-22808", 
           "CVE-2021-22726", "CVE-2021-22708", "CVE-2021-22818", 
           "CVE-2021-22774", "CVE-2022-22807", "CVE-2021-22773", 
           "CVE-2021-22721", "CVE-2018-7778", "CVE-2018-7801", "CVE-2021-22821", "CVE-2021-22707", "CVE-2021-22822", "CVE-2021-22723", "CVE-2018-7800", "CVE-2018-16671", "CVE-2018-16670", "CVE-2018-16668", "CVE-2018-12634", "CVE-2018-17922", "CVE-2018-17918", "CVE-2024-25999", "CVE-2018-16672", "CVE-2021-34591", "CVE-2016-5809", "CVE-2017-12718", "CVE-2018-16669", "CVE-2023-52096", "CVE-2023-49958", "CVE-2023-49957", "CVE-2023-49956", "CVE-2023-49955", "CVE-2012-1990", "CVE-2020-15912", "CVE-2016-2278", "CVE-2022-0878", "CVE-2024-20465", "CVE-2018-0255", "CVE-2018-0172", "CVE-2018-0161", "CVE-2018-0156"}

# Create the network graph
def create_network_graph(weighted):
    G = nx.Graph()
    hosts = ["AS", "LMS", "CSMS", "CSC", "CS1", "CS2", "CS3", "RTS", "PM1", "PM2", "PM3", "CST", "EV1", "EV2", "EVSE1", "EVSE2", "EVSE3", "EVSE4", "EVSE5", "EVSE6", "DBS", "SW1", "SW2", "SW3", "GW", "MQTT"]
    G.add_nodes_from(hosts)
    
    dependencies = [
        ("AS", "LMS"), ("AS", "RTS"), ("RTS", "PM1"), ("RTS", "PM2"), ("RTS", "PM3"), ("PM1", "CS2"), ("CS2", "EVSE4"), ("CS2", "EVSE5"), ("CS2", "SW1"), ("SW1", "CSC"), ("CSC", "MQTT"), ("SW1", "CS1"), ("CS1", "CST"), ("CS1", "EVSE1"), ("EVSE1", "EV1"), ("CS1", "EVSE2"), ("CS1", "PM2"), ("CS1", "EVSE3"), ("SW1", "GW"), ("CSC", "SW2"), ("GW", "SW2"), ("SW2", "CS3"), ("CS3", "EVSE6"), ("CS3", "PM3"), ("GW", "SW3"), ("LMS", "SW3"), ("SW3", "CSMS"), ("CSMS", "DBS"), ("CSC", "SW3"), ("EV2", "EVSE2")
    ]
    weights = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 1, 1
    ]
    G.add_edges_from(dependencies)
    if weighted == True:
        for i in range(len(dependencies)):
            G.edges[dependencies[i]]["weight"] = weights[i]
    else:
        for i in range(len(dependencies)):
            G.edges[dependencies[i]]["weight"] = 1
#    print(G.edges[dependencies[1]])
#    sys.exit(0)
    return G, hosts

# Prepare vulnerability data
def prepare_vulnerability_data(vulnerability_data):
    #epss = {v.CVE: v.EPSS for v in vulnerability_data}
    epss = {}
    impact_scores = {}
    host_vulnerabilities = {}
    all_vulnerabilities = set()
    for v in vulnerability_data:
    	epss[v.CVE] = v.EPSS
    	impact_scores[v.CVE] = v.impact
    	if not v.host in host_vulnerabilities:
    		host_vulnerabilities[v.host] = set()
    	host_vulnerabilities[v.host].add(v.CVE)
    	all_vulnerabilities.add(v.CVE)	
#    impact_scores = {v.CVE: v.impact for v in vulnerability_data}
#    host_vulnerabilities = {v.host: [] for v in vulnerability_data}
    
#    for v in vulnerability_data:
#        host_vulnerabilities[v.host.append(v.CVE)]
    
    return epss, impact_scores, host_vulnerabilities, all_vulnerabilities

def neighborsOf(G,host):
	neighbors = []
	for e in G.edges(host):
		neighbors.append(e[1])
#	print(neighbors)
#	sys.exit(0)	
	return neighbors
	
# Function to calculate EPSS
def EPSS(host):
    if host not in host_vulnerabilities:
#    	print(f"Warning: {host} not found in host_vulnerabilities.")
    	return 0 	
    sumEPSS = 0
    for v in host_vulnerabilities[host]:
    	sumEPSS += epss[v]
    if len(host_vulnerabilities[host]) > 0:
    	return sumEPSS/len(host_vulnerabilities[host])
    return 0

# Function to calculate impact
def impact(host):
    if host not in host_vulnerabilities:
#    	print(f"Warning: {host} not found in host_vulnerabilities.")
    	return 0 	
    sumImpact = 0
    for v in host_vulnerabilities[host]:
    	sumImpact += impact_scores[v]
    if len(host_vulnerabilities[host]) > 0:
    	return sumImpact/len(host_vulnerabilities[host])
    return 0
    
def numVulns(h):
    if not h in host_vulnerabilities:
    	return 0
    else:
          return len(host_vulnerabilities[h])
          
def c(h, v, reference_host_vulnerabilities):
    
    if h in reference_host_vulnerabilities:
        if v in reference_host_vulnerabilities[h]:
            return 1
        else:
            return 0    
    else:
        return 0    

# Calculate system exposure function
def calculate_system_exposure(hosts, vulnerabilities, c, reference_host_vulnerabilities):
    sysExp = 0
#    sys.exit(0)
    for v in vulnerabilities:
        frequency = (1 / len(hosts)) * (sum(c(h, v, reference_host_vulnerabilities) for h in hosts))
        epss_s = epss[v]
        impact_value = impact_scores[v]
        hostExposure = epss_s * impact_value
        sysExp += frequency * hostExposure
            
    return sysExp
    
def dijkstra_attacker_algorithm(graph, entry_point):
#    print(graph.nodes)
#    print(graph.nodes[entry_point])
    reached_hosts = set()
    reached_hosts.add(entry_point)

    shortest_paths = nx.single_source_dijkstra_path(graph, entry_point, weight='weight')

    all_paths = set ()
    for target, path in shortest_paths.items():
        if target != entry_point:
            all_paths.add(Path(target, path))
            reached_hosts.add(target)
    
#    print(shortest_paths)
#    print(all_paths)
#    sys.exit(0)
    return all_paths

def my_attacker_algorithm(system_model, entry_point, vulnerabilities, get_connections):

    # Initialize reached hosts, queue, and paths
    reached_hosts = {entry_point}               # R <- {e}
    queue = deque()
    queue.append(Path(entry_point, [entry_point])) # Q <- [(e, [e])]
    paths = set()                               # P <- ∅

    # While there are hosts in the queue
    while queue:
        # Pop the current host and path
        path = queue.pop()
        
        # Initialize candidates list
        candidates = []

        # Find each neighbor of the current host
        for neighbor in neighborsOf(system_model, path.destination):
            if neighbor not in reached_hosts:
                # Get properties for the candidate host
                connections = len(neighborsOf(system_model, neighbor))
                epss_value = epss.get(neighbor, 0)
                impact_value = impact(neighbor)
                
                # Add candidate to the list
                candidates.append((neighbor, connections, epss_value, impact_value))
        
        # If there are no candidates, add the current path to paths
        if not candidates:
            paths.add(path)
        else:
            # Sort candidates by connections, EPSS, and impact
            candidates.sort(key=lambda x: (x[1], x[2], x[3]), reverse=True)

            # Process each candidate
            while candidates:
                # Select the next host to visit
                next_host, _, _, _ = candidates.pop()
                
                # Add next host to reached hosts and update queue with the new path
                reached_hosts.add(next_host)
                new_path = Path(next_host,path.steps.copy())
                new_path.addStep(next_host)
                queue.append(new_path)
    
    return paths

def c_prime(h, v, path, patches, reference_host_vulnerabilities):
#    print(type(h),type(v),type(path),type(patches))
#    sys.exit(0)
    # If host h is on the current path and v has a patch, return 0
    return 0 if h in path.steps and v in patches else c(h, v, reference_host_vulnerabilities)
    
def defender_algorithm_with_patching(system_model, paths, patches, calculate_system_exposure):

    H, V, _ = system_model  # Unpack system model
    path_exposures = {}
    

    # Iterate over each path to calculate exposure after hypothetical patching
    for path in paths:
        updated_host_vulnerabilities = copy.deepcopy(host_vulnerabilities)
        for h in path.steps:
            if h in updated_host_vulnerabilities:
                for v in updated_host_vulnerabilities[h].copy():
                     if c_prime(h, v, path, patches, updated_host_vulnerabilities) == 0:
#                         print("patching " + v + " on " + h)
                         updated_host_vulnerabilities[h].remove(v)
#                    print(h, v, path, patches, c_prime(h, v, path, patches, updated_host_vulnerabilities))
                
#    	print(path)
        # Define modified vulnerability function c_prime for each path
             

        # Calculate system exposure
        exposure = calculate_system_exposure(H, V, c, updated_host_vulnerabilities)
        print(path, exposure)
        path_exposures[path] = exposure

    # Select the path with the highest exposure
    most_exposed_path = min(path_exposures, key=path_exposures.get)
    
    return most_exposed_path, path_exposures[most_exposed_path]
    

def defender_algorithm_with_incremental_patching(system_model, path, patches, calculate_system_exposure):

    H, V, _ = system_model  # Unpack system model
    path_exposures = {}
    

    # Iterate over each step in the path to calculate exposure after hypothetical patching a single vulnerability incrementally
    updated_host_vulnerabilities = copy.deepcopy(host_vulnerabilities)
    for h in path.steps:
        if h in updated_host_vulnerabilities:
            for v in updated_host_vulnerabilities[h].copy():
                if c_prime(h, v, path, patches, updated_host_vulnerabilities) == 0:
#                     print("patching " + v + " on " + h)
                    updated_host_vulnerabilities[h].remove(v)
                    exposure = calculate_system_exposure(H, V, c, updated_host_vulnerabilities)
                    print("Removed: " + v + " Resulting risk:" + str(exposure))
#                    print(h, v, path, patches, c_prime(h, v, path, patches, updated_host_vulnerabilities))
                
#    	print(path)
        # Define modified vulnerability function c_prime for each path
             

        # Calculate system exposure
#        exposure = calculate_system_exposure(H, V, c, updated_host_vulnerabilities)
#       print(path, exposure)
#        path_exposures[path] = exposure

    # Select the path with the highest exposure
#    most_exposed_path = min(path_exposures, key=path_exposures.get)
    
#    return most_exposed_path, path_exposures[most_exposed_path]


# Execution

if len(sys.argv) != 4:
    print("Usage: TAP <entry_point> <attacker_algo> <weighted> ", file = sys.stderr)
    sys.exit(-1)
entry_point = sys.argv[1]
attacker_algo = sys.argv[2]
weighted = sys.argv[3]
if weighted == "true":
    weighted = True
elif weighted == "false":
    weighted = False
else: 
    print("invalid weighted value, pass (true/false)", file = sys.stderr)
    sys.exit(-1)
        
vulnerability_data = get_vulnerability_data()
epss, impact_scores, host_vulnerabilities, all_vulnerabilities = prepare_vulnerability_data(vulnerability_data)
network_graph, hosts = create_network_graph(weighted)
if not entry_point in network_graph.nodes:
    print("invalid entry point, exiting", file = sys.stderr)
    sys.exit(-1)

#neighborsOf(network_graph, "LMS")


# Calculate initial system exposure
initial_exposure = calculate_system_exposure(hosts, all_vulnerabilities, c, host_vulnerabilities)
#print(initial_exposure)

# Attack simulation
#entry_point = "CSC"
if attacker_algo == "dijkstra":
    attack_paths = dijkstra_attacker_algorithm(network_graph, entry_point)
elif attacker_algo == "mine":    
    attack_paths = my_attacker_algorithm(network_graph, entry_point, host_vulnerabilities, lambda h: len(list(network_graph.neighbors(h))))
else :
    print("No attack algorithms specified, exiting", file = sys.stderr)
#print(attack_paths)
#sys.exit(0)
# Defender patching response
def visualize_graph(G, most_exposed_path):
    most_exposed_path_list = most_exposed_path.steps 

    path_edges = list(zip(most_exposed_path_list, most_exposed_path_list[1:]))
    
    # Visualizing the graph
    pos = nx.spring_layout(G, k=0.4)  # positions for all nodes
    nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=500, font_size=8)
    nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='red', width=1)
    
    plt.title("Network Graph with Most Exposed Path Highlighted")
    plt.show()
    
most_exposed_path, exposure_after_patching = defender_algorithm_with_patching((hosts, all_vulnerabilities, lambda h, v: 1), attack_paths, patches, calculate_system_exposure)

# Calculate new system exposure after patching
new_exposure = calculate_system_exposure(hosts, all_vulnerabilities, c, host_vulnerabilities)

# Output results
print("Initial System Exposure:", initial_exposure)
print("Most Exposed Attack Path:", most_exposed_path)
print("Exposure After Patching:", exposure_after_patching)

defender_algorithm_with_incremental_patching((hosts, all_vulnerabilities, lambda h, v: 1), most_exposed_path, patches, calculate_system_exposure)

if __name__ == "__main__":
    vulnerability_data = get_vulnerability_data()
    epss, impact_scores, host_vulnerabilities, all_vulnerabilities = prepare_vulnerability_data(vulnerability_data)
    
    G, hosts = create_network_graph(weighted=True)
    visualize_graph(G, most_exposed_path)
