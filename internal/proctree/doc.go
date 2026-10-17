// Package proctree starts a program at the head of a process tree and ends the
// whole tree. A browser is many processes: killing the first of them alone
// left the renderers, the GPU and the network processes running, orphaned,
// after the run that started them had ended.
package proctree
