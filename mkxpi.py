#!/usr/bin/env python

'''
Makes an .xpi file for a Mozilla extension.

Expecting this tree structure:

    foxy/
        ext/
            chrome.manifest
            components/
            contents/
            install.rdf
            locale/
        other_subdirs/       (ignored)
            somefiles        (ignored)

$ ./mkxpi.py ../foxy
will take (most of) the contents of
    foxy/ext/
and zip it to
    foxy_1.xpi  (or if that exists, then foxy_2.xpi, etc)
'''

import os
import shlex
import subprocess
import sys


def get_latest_xpi(dpath, fname):
    '''Return highest num of fname_num.xpi found.'''
    if fname.endswith('.xpi'):
        fname = fname[:-4]
    names = os.listdir(os.path.split(dpath)[0])
    names = [n for n in names if n.endswith('xpi')]
    names = [n for n in names if n.startswith(fname)]
    latest = 0
    length = len(fname) + 1   # +1 for the _
    for name in names:
        num = name[length:-4]
        try:
            num = int(num, 10)
            if num > latest:
                latest = num
        except:
            pass

    return latest


def get_ext_root_dir(topdir):
    '''Return dir in which actual extension code lives.'''
    files = []
    for dpath, dnames, fnames in os.walk(topdir):
        for f in fnames:
            if (f == 'install.rdf'):
                files.append(os.path.join(dpath, f))

    if len(files) < 1:
        print 'Error:  could not find "install.rdf" under "{0}"'.format(topdir)
        return ''
    elif len(files) > 1:
        print 'Error:  found more than one "install.rdf" under "{0}"'.format(topdir)
        return ''

    return os.path.split(files[0])[0]


def get_files(topdir):
    '''Return a list of filepaths to include in .xpi.'''
    files = []
    for dpath, dnames, fnames in os.walk(topdir):
        for d in dnames:
            if (d.startswith('test') or
                    d == '.komodotools'):
                continue
            files.append(os.path.join(dpath, d))
        for f in fnames:
            if (f == '.DS_Store' or
                    f.endswith('.swp') or
                    f.endswith('.komodoproject') or
                    f.endswith('.project')):
                continue
            files.append(os.path.join(dpath, f))

    print 'Found {} files to zip.'.format(len(files))
    return files


def make_xpi(ext_root, xpi_path, fnames):
    '''Create the .xpi file.'''
    names = ''
    # .xpi requires relative paths
    ext_root_len = len(ext_root) + 1
    for name in fnames:
        names += name[ext_root_len:] + ' '
    os.chdir(ext_root)
    cmd_str = 'zip -b /tmp {0} {1}'.format(xpi_path, names)
    cmd = shlex.split(cmd_str)
    if 0 == subprocess.call(cmd):
        print 'Wrote to "{}".'.format(xpi_path)


def usage():
    if './' == sys.argv[0][:2]:
        prog = sys.argv[0][2:]
    else:
        prog = sys.argv[0]
    print 'Usage:  {0} PATH_TO_TOPDIR'.format(prog)
    print
    print 'Zip the contents of TOPDIR/ext/ to TOPDIR_NUM.xpi,'
    print 'where NUM is the current highest plus 1.'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        sys.exit()

    topdir = os.path.abspath(sys.argv[1])
    xpi_stem = os.path.basename(topdir)
    xpi_num = get_latest_xpi(topdir, xpi_stem) + 1
    xpi_name = xpi_stem + '_' + str(xpi_num) + '.xpi'
    xpi_path = os.path.join(os.path.split(topdir)[0], xpi_name)
    print 'Planning to write to "{}".'.format(xpi_path)
    ext_root = get_ext_root_dir(topdir)
    if ext_root == '':
        sys.exit()
    fnames = get_files(ext_root)
    make_xpi(ext_root, xpi_path, fnames)

