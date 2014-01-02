import os
import time
import subprocess

SHOW_LOCAL_COMM = False

lsof_cmd = ["sudo", "lsof", "-n", "-i", "4", "-a"]
whois_cmd = ["whois"]
ifconfig_cmd = ["ifconfig"]
clear_cmd = "clear"

def main():

	while True:
		output = subprocess.Popen(lsof_cmd, stdout=subprocess.PIPE)
		stdout = output.communicate()[0]
		records = grep(stdout, "Google")
		proc_info = collate(records)
		update_whois(proc_info)
		sketchy_procs = ""
		for pid in proc_info:
			p = proc_info[pid]
			if (SHOW_LOCAL_COMM == False and p.local_comm_only == False) or (SHOW_LOCAL_COMM == True):
				sketchy_procs += str(p)
		clear()
		sketchy_procs = sketchy_procs.strip()
		if len(sketchy_procs) == 0:
			print "No sketchy Google connections."
		else:
			print sketchy_procs
		time.sleep(1)

#return lines containing certain search string
def grep(stdout, s):
	result = []
	lines = stdout.split('\n')
	for line in lines:
		if s in line:
			#print line
			fields = line.split()
			result.append(fields)
	return result

def collate(records):
	proc_info = {}
	for r in records:
		pid = r[1]
		if pid not in proc_info.keys():
				proc_info[pid] = Process(pid=pid, name=r[0])
		connection = r[8].split('->')
		if len(connection) == 2:
			ip,port = connection[0].split(":")
			source = SocketAddress(ip,port)
			ip,port = connection[1].split(":")
			dest = SocketAddress(ip,port)
			proc_info[pid].add_connection(source, dest)
		elif len(connection) == 1:
			ip,port = connection[0].split(":")
			open_port = SocketAddress(ip,port)
			proc_info[pid].add_listener(open_port)
		else:
			print "Weird record format:", r 
	return proc_info

def update_whois(proc_info):
	for pid in proc_info:
		p = proc_info[pid]
		p.update_whois()
		
def get_my_ips():
	output = subprocess.Popen(ifconfig_cmd, stdout=subprocess.PIPE)
	stdout = output.communicate()[0]
	records = grep(stdout, "inet ")
	return [r[1] for r in records]

def clear():
	os.system(clear_cmd)



class Process(object):
	def __init__(self, pid=None, name=None, connections=[], listeners=[]):
		self.pid = pid
		self.name = name
		self.destinations = {}
		self.local_comm_only = True
		self.add_connections(connections) #[(SocketAddress, SocketAddress)]
		self.add_listeners(listeners) #[SocketAddress]

	def __str__(self):
		s = str(self.name) + " (PID: " + str(self.pid) + ")\n"
		s += "   Destinations:\n" + self.str_destinations()
		s += "   Connections:\n" + self.str_connections()
		if SHOW_LOCAL_COMM == True:
			s += "   Listeners:\n" + self.str_listeners()
		return s

	def str_connections(self):
		s = ""
		if len(self.connections) == 0:
			s = "\tNone.\n"
		else:
			for i in self.connections:
				s += "\t" + str(i[0]) + " -> " + str(i[1]) + "\n"
		return s
	def str_listeners(self):
		s = ""
		if len(self.listeners) == 0:
			s = "\tNone.\n"
		else:
			for i in self.listeners:
				s += "\t" + str(i) + "\n"
		return s
	def str_destinations(self):
		s = ""
		if len(self.destinations) == 0:
			s = "\tNone.\n"
		else:
			destinations_by_count = [[self.destinations[name], name] for name in self.destinations]
			destinations_by_count.sort()
			destinations_by_count.reverse()
			for d in destinations_by_count:
				s += "\t" + str(d[1]) + " (" + str(d[0]) + ")\n"
		return s

	def add_connections(self, conns):
		if conns == []:
			self.connections = []
		for c in conns:
			self.add_connection(c[0],c[1])
	def add_connection(self, source, dest):
		self.connections.append((source, dest))
		if dest.ip not in get_my_ips():
			self.local_comm_only = False

	def add_listeners(self, listens):
		if listens == []:
			self.listeners = []
		for l in listens:
			self.add_listener(l)
	def add_listener(self, open_socket):
		self.listeners.append(open_socket)

	def update_whois(self):
		for (source, dest) in self.connections:
			source.update_owner()
			dest.update_owner()
		for listener in self.listeners:
			listener.update_owner()
		self.update_destinations()

	def update_destinations(self):
		self.destinations = {}
		for (source, dest) in self.connections:
			if dest.owner not in self.destinations:
				self.destinations[dest.owner] = 1
			else:
				self.destinations[dest.owner] += 1

class SocketAddress(object):
	def __init__(self, ip=None, port=None, owner=None):
		self.ip = ip
		self.port = port
		self.owner = owner

	def __str__(self):
		return str(self.ip) + ":" + str(self.port) + " (" + str(self.owner) + ")"

	def update_owner(self):
		if self.ip == None:
			owner = None
		elif self.ip in get_my_ips():
			owner = "me"
		else:
			output = subprocess.Popen(whois_cmd + [self.ip], stdout=subprocess.PIPE)
			stdout = output.communicate()[0]
			owner = grep(stdout, "OrgName")
			if owner == []:
				lines = stdout.split("\n")
				for i in range(len(lines)):
					if lines[i] != '' and lines[i][0] != "#":
						owner = lines[i]
				owner = owner.split("(")[0]
			else:
				owner = "".join(i + " " for i in owner[0][1:]).rstrip()
		self.owner = owner


if __name__=="__main__":
	main()
