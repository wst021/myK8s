#!/bin/bash
nohup java -jar jenkins.war --httpPort=9090 2>&1 > jenkins.log &