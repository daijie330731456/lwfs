" lwfs.vim: GNU Vim Syntax file for LWFS .vol specification
" Copyright (C) 2007-2009 LW, Inc. <http://www.lw.com>
" This file is part of LWFS.
"
" LWFS is free software; you can redistribute it and/or modify
" it under the terms of the GNU General Public License as published
" by the Free Software Foundation; either version 3 of the License,
" or (at your option) any later version.
"
" LWFS is distributed in the hope that it will be useful, but
" WITHOUT ANY WARRANTY; without even the implied warranty of
" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
" General Public License for more details.
"
" You should have received a copy of the GNU General Public License
" along with this program.  If not, see
" <http://www.gnu.org/licenses/>.
"
" Last Modified: Wed Aug  1 00:47:10 IST 2007
" Version: 0.8 

syntax clear
syntax case match

setlocal iskeyword+=-
setlocal iskeyword+=%
setlocal iskeyword+=.
setlocal iskeyword+=*
setlocal iskeyword+=:
setlocal iskeyword+=,


"************************************************************************
" Initially, consider everything an error. Then start eliminating one
"   field after the other. Whatever is not eliminated (due to defined
"   properties) is an error - Multiples Values for a key
"************************************************************************
syn match lwfsError /[^ 	]\+/ skipwhite
syn match lwfsComment "#.*" contains=lwfsTodo

syn keyword	lwfsTodo	contained TODO FIXME NOTE

"------------------------------------------------------------------------
" 'Type' Begin
"------------------------------------------------------------------------
" Handle all the 'Type' keys and values. Here, a '/' is used to separate
" the key-value pair, they are clubbed together for convenience
syn match lwfsType "^\s*type\s\+" skipwhite nextgroup=lwfsTypeKeyVal

syn match lwfsTypeKeyVal contained "\<protocol/\(client\|server\)\>"
syn match lwfsTypeKeyVal contained "\<cluster/\(unify\|afr\|stripe\)\>"
syn match lwfsTypeKeyVal contained "\<debug/\(trace\)\>"
syn match lwfsTypeKeyVal contained "\<encryption/\(rot-13\)\>"
syn match lwfsTypeKeyVal contained "\<storage/\(posix\)\>"
"syn match lwfsTypeKeyVal contained "\<features/\(trash\)\>"
syn match lwfsTypeKeyVal contained "\<features/\(trash\|posix-locks\|fixed-id\|filter\)\>"
syn match lwfsTypeKeyVal contained "\<performance/\(io-threads\|write-behind\|io-cache\|read-ahead\)\>"
"------------------------------------------------------------------------
" 'Type' End
"------------------------------------------------------------------------


"************************************************************************

"------------------------------------------------------------------------
" 'Volume' Begin
"------------------------------------------------------------------------
" NOTE 1: Only one volume name allowed after 'volume' keyword
" NOTE 2: Multiple volumes allowed after 'subvolumes'
" NOTE 3: Some other options (like remote-subvolume, namespace etc) use
"   volume name (single)
syn match lwfsVol "^\s*volume\s\+" nextgroup=lwfsVolName
syn match lwfsVolName "\<\k\+" contained

syn match lwfsVol "^\s*subvolumes\s\+" skipwhite nextgroup=lwfsSubVolName
syn match lwfsSubVolName "\<\k\+\>" skipwhite contained nextgroup=lwfsSubVolName

syn match lwfsVol "^\s*end-volume\>"
"------------------------------------------------------------------------
" 'Volume' End
"------------------------------------------------------------------------





"------------------------------------------------------------------------
" 'Options' Begin
"------------------------------------------------------------------------
syn match lwfsOpt "^\s*option\s\+" nextgroup=lwfsOptKey


syn keyword lwfsOptKey contained transport-type skipwhite nextgroup=lwfsOptValTransportType
syn match lwfsOptValTransportType contained "\<\(tcp\|ib\-verbs\|ib-sdp\)/\(client\|server\)\>"

syn keyword lwfsOptKey contained remote-subvolume skipwhite nextgroup=lwfsVolName

syn keyword lwfsOptKey contained auth.addr.ra8.allow auth.addr.ra7.allow auth.addr.ra6.allow auth.addr.ra5.allow auth.addr.ra4.allow auth.addr.ra3.allow auth.addr.ra2.allow auth.addr.ra1.allow auth.addr.brick-ns.allow skipwhite nextgroup=lwfsOptVal

syn keyword lwfsOptKey contained client-volume-filename directory trash-dir skipwhite nextgroup=lwfsOpt_Path
syn match lwfsOpt_Path contained "\s\+\f\+\>"

syn keyword lwfsOptKey contained debug self-heal encrypt-write decrypt-read mandatory nextgroup=lwfsOpt_OnOff
syn match lwfsOpt_OnOff contained "\s\+\(on\|off\)\>"

syn keyword lwfsOptKey contained flush-behind non-blocking-connect nextgroup=lwfsOpt_OnOffNoYes
syn keyword lwfsOpt_OnOffNoYes contained on off no yes

syn keyword lwfsOptKey contained page-size cache-size nextgroup=lwfsOpt_Size

syn keyword lwfsOptKey contained fixed-gid fixed-uid cache-seconds page-count thread-count aggregate-size listen-port remote-port transport-timeout inode-lru-limit nextgroup=lwfsOpt_Number

syn keyword lwfsOptKey contained alu.disk-usage.entry-threshold alu.disk-usage.exit-threshold nextgroup=lwfsOpt_Size

syn keyword lwfsOptKey contained alu.order skipwhite nextgroup=lwfsOptValAluOrder
syn match lwfsOptValAluOrder contained "\s\+\(\(disk-usage\|write-usage\|read-usage\|open-files-usage\|disk-speed\):\)*\(disk-usage\|write-usage\|read-usage\|open-files-usage\|disk-speed\)\>"

syn keyword lwfsOptKey contained alu.open-files-usage.entry-threshold alu.open-files-usage.exit-threshold alu.limits.max-open-files rr.refresh-interval random.refresh-interval nufa.refresh-interval nextgroup=lwfsOpt_Number

syn keyword lwfsOptKey contained nufa.local-volume-name skipwhite nextgroup=lwfsVolName

syn keyword lwfsOptKey contained ib-verbs-work-request-send-size ib-verbs-work-request-recv-size nextgroup=lwfsOpt_Size
syn match lwfsOpt_Size contained "\s\+\d\+\([gGmMkK][bB]\)\=\>"

syn keyword lwfsOptKey contained ib-verbs-work-request-send-count ib-verbs-work-request-recv-count ib-verbs-port nextgroup=lwfsOpt_Number

syn keyword lwfsOptKey contained ib-verbs-mtu nextgroup=lwfsOptValIBVerbsMtu
syn match lwfsOptValIBVerbsMtu "\s\+\(256\|512\|1024\|2048\|4096\)\>" contained

syn keyword lwfsOptKey contained ib-verbs-device-name nextgroup=lwfsOptVal

syn match lwfsOpt_Number contained "\s\+\d\+\>"

syn keyword lwfsOptKey contained scheduler skipwhite nextgroup=lwfsOptValScheduler
syn keyword lwfsOptValScheduler contained rr alu random nufa

syn keyword lwfsOptKey contained namespace skipwhite nextgroup=lwfsVolName

syn keyword lwfsOptKey contained lock-node skipwhite nextgroup=lwfsVolName



syn keyword lwfsOptKey contained alu.write-usage.entry-threshold alu.write-usage.exit-threshold alu.read-usage.entry-threshold alu.read-usage.exit-threshold alu.limits.min-free-disk nextgroup=lwfsOpt_Percentage

syn keyword lwfsOptKey contained random.limits.min-free-disk nextgroup=lwfsOpt_Percentage
syn keyword lwfsOptKey contained rr.limits.min-disk-free nextgroup=lwfsOpt_Size

syn keyword lwfsOptKey contained nufa.limits.min-free-disk nextgroup=lwfsOpt_Percentage

syn match lwfsOpt_Percentage contained "\s\+\d\+%\=\>"









syn keyword lwfsOptKey contained remote-host bind-address nextgroup=lwfsOpt_IP,lwfsOpt_Domain
syn match lwfsOpt_IP contained "\s\+\d\d\=\d\=\.\d\d\=\d\=\.\d\d\=\d\=\.\d\d\=\d\=\>"
syn match lwfsOpt_Domain contained "\s\+\a[a-zA-Z0-9_-]*\(\.\a\+\)*\>"

syn match lwfsVolNames "\s*\<\S\+\>" contained skipwhite nextgroup=lwfsVolNames

syn keyword lwfsOptKey contained block-size replicate skipwhite nextgroup=lwfsOpt_Pattern

syn match lwfsOpt_Pattern contained "\s\+\k\+\>"
syn match lwfsOptVal contained "\s\+\S\+\>"





hi link lwfsError Error
hi link lwfsComment Comment

hi link lwfsVol keyword

hi link lwfsVolName function
hi link lwfsSubVolName function

hi link lwfsType Keyword
hi link lwfsTypeKeyVal String

hi link lwfsOpt Keyword

hi link lwfsOptKey Special
hi link lwfsOptVal Normal

hi link lwfsOptValTransportType String
hi link lwfsOptValScheduler String
hi link lwfsOptValAluOrder String
hi link lwfsOptValIBVerbsMtu String

hi link lwfsOpt_OnOff String
hi link lwfsOpt_OnOffNoYes String


" Options that require
hi link lwfsOpt_Size PreProc
hi link lwfsOpt_Domain PreProc
hi link lwfsOpt_Percentage PreProc
hi link lwfsOpt_IP PreProc
hi link lwfsOpt_Pattern PreProc
hi link lwfsOpt_Number Preproc
hi link lwfsOpt_Path Preproc



let b:current_syntax = "lwfs"
