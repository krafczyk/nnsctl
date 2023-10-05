import networkx as nx
import matplotlib.pyplot as plt

def parse_ip_addr(file):
    nodes = []
    with open(file, 'r') as f:
        for line in f:
            if "inet " in line:
                ip = line.split()[1].split('/')[0]
                nodes.append(ip)
    return nodes

def parse_ip_route(file):
    edges = []
    with open(file, 'r') as f:
        for line in f:
            parts = line.split()
            dest = parts[0]
            gateway = parts[2] if 'via' in line else None
            if gateway:
                edges.append((gateway.split('/')[0], dest.split('/')[0]))
    return edges

if __name__ == "__main__":
    nodes = parse_ip_addr('ip_addr.txt')
    edges = parse_ip_route('ip_route.txt')

    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True)
    plt.show()
