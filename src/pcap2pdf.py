#!/usr/bin/env python3
# -*- coding: utf8 -*-

# `pcap2pdf` creates PDF report of internet/network activity from pcap/pcapng file
# for each device (MAC address) found in the capture file.
#
# To be used with (shell script) `pcap2pdf` or directly with text file produced by `wireowl`.
#
# This file is part of pcap2pdf which is released under GNU GPLv2 license.
#
# Copyright 2021, 2022 Jiri Rozvaril <rozvara at vync dot org>

import os
import sys
import stat
import time
import argparse
from fpdf import FPDF
from PIL import Image, ImageDraw, ImageFont
from wireowl_backend import TrafficInspector, PacketReader
from wireowl_common import rel_time, fmt_time

VERSION="0.2.6"

class PDF(FPDF):
    # visual constants
    c_row_height = 4
    c_cell_height = 1
    c_font = 'DejaVuSans'
    c_ruler_in_header = False
    c_ruler_sections = 6
    c_header_color = 180  # grey
    #
    timezone_correction = time.timezone - 3600*time.localtime().tm_isdst

    def set_header_values(self, macaddr, starttime, duration, ip, hostname, anonymize):
        self.d_start_time = starttime
        self.d_duration = duration
        self.d_ip = ip
        self.d_hostname = hostname
        self.d_anonymize = anonymize
        if anonymize:
            self.d_macaddr = macaddr[:4]+'x:xx:xx:xx:x'+macaddr[-1:]
        else:
            self.d_macaddr = macaddr

    def report_font(self):
        self.set_font(self.c_font, '', 8)
        self.set_draw_color(0)  # black
        self.set_text_color(0)

    def header(self):
        self.report_font()
        self.set_text_color(self.c_header_color)
        txt =  f"Device: {self.d_macaddr}\n"
        if not self.d_anonymize:
            if self.d_ip:
                txt += f"IP address: {self.d_ip}\n"
            if self.d_hostname:
                txt += f"Hostname: {self.d_hostname}\n"
        txt += f"Recorded: {fmt_time(self.d_start_time-self.timezone_correction,2)}\n"
        self.multi_cell(0, 4, txt, 0, 'L', False)
        self.ln(1*self.c_row_height)
        if self.c_ruler_in_header:
            self.draw_ruler(self.l_margin, self.w-self.r_margin)
        self.report_font()

    def footer(self):
        self.set_y(-10)  # Position from bottom
        self.set_font(self.c_font, '', 7)
        self.set_text_color(180)  # grey
        self.cell(0, 10, "Page " + str(self.page_no()) + " of {nb}", 0, 0, 'C')

    # title/heading of chapter
    def report_chapter(self, label):
        self.report_font()
        self.set_line_width(0.2)
        self.cell(0, 9, label, 1, 1, 'C')  # fpdf.cell(w, h, txt, border, ln, align, fill, link)
        self.ln(self.c_row_height)

    # time ruler
    def draw_ruler(self, lx, rx):
        self.set_font(self.c_font, '', 6)
        self.set_draw_color(0)
        self.set_text_color(0)
        rm = self.r_margin  # ruler text goes behind margin, save to restore later
        lm = self.l_margin
        self.set_right_margin(0)
        self.set_left_margin(0)
        self.set_line_width(0.2)
        section = (rx-lx)/self.c_ruler_sections
        for i in range(0, self.c_ruler_sections+1):
            self.line(lx+i*section, self.get_y()+self.c_row_height, lx+i*section,
                self.get_y()+2*self.c_row_height)
            txt = rel_time(self.d_duration * (i/self.c_ruler_sections), 1)
            self.set_x(lx+i*section - self.get_string_width(txt+'A')/2)
            self.write(self.c_row_height, txt)
        self.set_right_margin(rm)
        self.set_left_margin(lm)
        self.report_font()
        self.ln(2.5*self.c_row_height)


# PDF report for one device
#
def create_pdf_report(backend, final_time, macaddr, show_cnames, anonymize):

    dev_stat = backend.get_device_statistics(macaddr, final_time)

    time_start = dev_stat['fa']  # 'first appearance' (time of first packet)
    time_end = final_time + dev_stat['la']  # 'last seen' is negative
    duration = time_end - time_start + 1

    pdf = PDF(orientation = 'P', unit = 'mm', format='A4')
    pdf.set_creator('pcap2pdf '+VERSION+' https://github.com/rozvara/pcap2pdf')
    pdf.alias_nb_pages()  # alias for the total number of pages (see footer)
    #
    # TODO Fedora /usr/share/fonts/dejavu-sans-fonts/
    #
    pdf.add_font(pdf.c_font, '',
        '/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf', uni=True)
    pdf.add_font(pdf.c_font, 'B',
        '/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf', uni=True)

    #
    # === Header (of each page) ===
    #
    pdf.set_header_values(macaddr, time_start, duration, dev_stat['ip'], dev_stat['hn'], anonymize)
    pdf.add_page()

    #
    # === Summary ===
    #
    pdf.report_chapter(f"Summary of {rel_time(duration,2)} of network activity")

    def stat_column(i, y, value, label, icon=''):
        widths = [ 0.225, 0.225, 0.10, 0.15, 0.15, 0.15 ]
        net_width = pdf.w - pdf.l_margin - pdf.r_margin
        center = pdf.l_margin + sum(widths[0:i])*net_width + widths[i]*net_width/2
        pdf.set_y(y)
        pdf.report_font()  # label normal
        pdf.set_x(center - pdf.get_string_width(label)/2)
        pdf.write(pdf.c_row_height, label)
        pdf.ln(pdf.c_row_height*1.2)
        pdf.set_font(pdf.c_font, 'B', 11)  # value bold
        txt = f"{value:,}".replace(",", " ")
        pdf.set_x(center - pdf.get_string_width(txt+icon)/2)
        if icon == '199':
            pdf.set_text_color(r=255, g=0, b=0)
            pdf.write(pdf.c_row_height, "↑  ")
        elif icon == '991':
            pdf.set_text_color(r=0, g=0, b=255)
            pdf.write(pdf.c_row_height, "↓  ")
        pdf.set_text_color(0)
        pdf.write(pdf.c_row_height, txt)

    y = pdf.get_y()
    stat_column(0, y, dev_stat['rx'],   "Received bytes", '991')  # 991/199 just for width
    stat_column(1, y, dev_stat['tx'],   "Sent bytes", '199')
    stat_column(2, y, dev_stat['conn'], "Endpoints")
    stat_column(3, y, dev_stat['dnsq'], "DNS queries")
    stat_column(4, y, dev_stat['dnsd'], "Unique domains")
    stat_column(5, y, dev_stat['pkts'], "Packets")

    pdf.report_font()
    pdf.ln(pdf.c_row_height*3)  # spacer

    #
    # === Endpoints with graphs ===
    #
    pdf.report_chapter(f"Network conversations per endpoint (IP address)")
    pdf.c_cell_height = 1.6  # 1.6 rows

    # sorted connections
    conns = backend.get_device_connections(macaddr, time_start)
    lst = list()
    for ip in conns.keys():
        lst.append([conns[ip]['fa'], ip])
    lst.sort()

    ip_address_width = 0  # width of longest IP address (using particular font)
    bytes_sent_width = 0
    for _, ip in lst:
        # prepare hyperlinks down and back
        conns[ip]['link_up'] = pdf.add_link()
        conns[ip]['link_down'] = pdf.add_link()
        # find the longest address
        ip_address_width = max(ip_address_width, pdf.get_string_width(ip))
        txt = f"{conns[ip]['tx']:,} B".replace(",", " ")
        bytes_sent_width = max(bytes_sent_width, pdf.get_string_width(txt))

    spacer = pdf.get_string_width('AAA')    # spacer between IP and graph
    lx = pdf.l_margin + ip_address_width + spacer  # left x of graph line
    rx = pdf.w - pdf.r_margin                      # right x, both in page units

    # width of graph bars between 0.4 and 1 mm, depends on length of traffic
    tl = min(1, max(0.4, (rx-lx)/duration))  # width
    graph_bars = int(1+ (rx-lx)/tl)  # total bars

    # once know the size of graph, recount timeline data to number of graph_bars
    interval_length = duration/graph_bars
    for ip in conns.keys():
        conns[ip]['tx_graph'] = [0]*graph_bars  # prepare array as zero values are not stored
        conns[ip]['rx_graph'] = [0]*graph_bars  # and we will sum those arrays later
        tx_data = backend.get_device_ip_tx_sec_graph(macaddr, ip, final_time)
        rx_data = backend.get_device_ip_rx_sec_graph(macaddr, ip, final_time)
        tx_data.pop('f'); tx_data.pop('l')
        rx_data.pop('f'); rx_data.pop('l')
        # order in graph array as index/time interval (from zero)
        for epoch in tx_data.keys():
            i = int((epoch-time_start)/interval_length)
            conns[ip]['tx_graph'][i] += tx_data[epoch]
        for epoch in rx_data.keys():
            i = int((epoch-time_start)/interval_length)
            # throw away incoming traffic after device was last seen sending data
            # e.g. retransmissions after disconnecting
            if i < len(conns[ip]['rx_graph']):
                conns[ip]['rx_graph'][i] += rx_data[epoch]

    def draw_graph(values, lx, rx, ys, tl, max_value, which):
        if which == 'r':
            # line only once
            pdf.set_draw_color(207, 207, 207)  # grey
            pdf.set_line_width(0.02)
            pdf.line(lx, ys, rx, ys)
            pdf.set_draw_color(r=0, g=0, b=127)  # blue for received
        else:
            pdf.set_draw_color(r=255, g=0, b=0)  # red for sent

        pdf.set_line_width(tl*0.9)  # 90 % of line width for "better" look
        for i, val in enumerate(values):
            pct = float(val/max_value)  # percentage
            if pct > 0:
                ln = round((pct*pdf.c_cell_height*pdf.c_row_height)//2)
                if ln < tl: ln = tl  # smallest height same as thickness
                if which == 'r':  # above or below line
                    pdf.line(lx+i*tl, ys+tl/2, lx+i*tl, ys+ln)
                else:
                    pdf.line(lx+i*tl, ys-tl/2, lx+i*tl, ys-ln)

    pdf.draw_ruler(lx, rx)

    # draw title on left and graph net to it
    for ip in conns.keys():
        pdf.cell(0, pdf.c_cell_height*pdf.c_row_height, '', '' )  # to fit on page or new page
        x = pdf.get_x()  # x,y (top left) of this cell
        y = pdf.get_y() - pdf.c_row_height  # for ky, ys
        ky = y + pdf.c_cell_height*pdf.c_row_height  # last y of cell
        ys = y + (pdf.c_cell_height+2)/2*pdf.c_row_height  # line center
        y = y + 1.1*pdf.c_row_height  # for text and set_link
        pdf.set_xy(x, y)
        pdf.set_link(conns[ip]['link_up'], y)

        # first row: IP
        pdf.set_x(lx - spacer-pdf.get_string_width(ip))  # align/right
        pdf.write(pdf.c_row_height * 0.6, ip, conns[ip]['link_down'])
        pdf.ln(pdf.c_row_height * 0.72)  # newline
        # second row: how much sent and where
        pdf.set_font(pdf.c_font, '', 6)
        if conns[ip]['cntr']:
            location = conns[ip]['cntr']
        elif conns[ip]['mult'] or conns[ip]['rsrv'] or conns[ip]['priv']:
            location = '~~'
        else:
            location = '??'
        txt = f"↑ {conns[ip]['tx']:,} B   {location}".replace(",", " ")
        pdf.set_x(lx - spacer-pdf.get_string_width(txt))  # align/right
        pdf.write(pdf.c_row_height * 0.6, txt)
        pdf.report_font()

        max_value = max(conns[ip]['rx_graph'] + [1])
        draw_graph(conns[ip]['rx_graph'], lx, rx, ys, tl, max_value, 'r')
        max_value = max(conns[ip]['tx_graph'] + [1])
        draw_graph(conns[ip]['tx_graph'], lx, rx, ys, tl, max_value, 't')
        pdf.set_draw_color(0)

        pdf.set_xy(x, ky)  # end of cell
        pdf.ln(pdf.c_row_height*(1.3))  # newline

    #
    # GROUPED IPs / DOMAINs
    #
    pdf.add_page()
    pdf.report_chapter(
        "Conversations grouped by the intersection of domain names and all matching endpoints")

    lx = pdf.l_margin  # new left margin
    rx = pdf.w - pdf.r_margin
    tl = (rx-lx)/graph_bars  # new graph bar width as graph is wider

    pdf.draw_ruler(lx, rx)

    # prepare data for groups creating
    ip2dom = backend.get_device_dnsreplies(macaddr)
    dom2ip = backend.get_device_domain_ips_list(macaddr)
    cnames = backend.get_device_dnscnames(macaddr)

    # expand cnames (update ip2dom)
    for dom in cnames.keys():
        if dom in dom2ip.keys():
            cname_ips = dom2ip[dom]  # set of ip
            for cnrec in cnames[dom]:  # for every cname add into ip2dom to group records
                for ip in cname_ips:
                    ip2dom[ip].update([cnrec])

    # groups (sort of full join)
    groups = list()
    for ip in conns.keys():
        ipset = set([ip])
        domset = ip2dom[ip] if ip in ip2dom.keys() else set()
        a_index = next((i for i, a_row in enumerate(groups) if domset.intersection(a_row[1])), -1)
        if a_index == -1:
            groups.append([ipset, domset])
        else:
            # update IP set and domains set
            ipset.update(groups[a_index][0])
            for dom in domset:  # add all IPs for each domain
                if dom in dom2ip.keys():  # must check because of cnames
                    ipset.update(dom2ip[dom])
            for ip2 in ipset:  # and all domains for each added IP
                domset.update(ip2dom[ip2])
            domset.update(groups[a_index][1])
            groups[a_index] = [ipset, domset]

    if not show_cnames:
        dom2remove = set()
        for dom in cnames.keys():
            dom2remove.update(cnames[dom])
        for i in range(len(groups)):
            groups[i][1] -= dom2remove

    # sum and sort
    groups_sum = list()
    for ipset, domset in groups:
        group_tx_graph = [0]*graph_bars
        group_rx_graph = [0]*graph_bars
        ipset = ipset.intersection(conns.keys())  # remove IPs the device didn't communicate to
        for ip in ipset:
            group_tx_graph = [v1+v2 for v1, v2 in zip(group_tx_graph, conns[ip]['tx_graph'])]
            group_rx_graph = [v1+v2 for v1, v2 in zip(group_rx_graph, conns[ip]['rx_graph'])]
        # sort to have most talkative first
        groups_sum.append([ipset, domset, group_tx_graph, group_rx_graph, group_tx_graph.count(0)])

    sorted_groups = sorted(groups_sum, key=lambda sortkey: sortkey[4])

    # print group graphs and list of connections
    pdf.c_cell_height = 3

    for ipset, domset, tx_graph, rx_graph, count in sorted_groups:
        # draw group graph
        # 3 for text + c_cell_height; to make sure it will fit to page, otherwise new page
        pdf.cell(0, (3+pdf.c_cell_height)*pdf.c_row_height, '', '' )
        y = pdf.get_y() - pdf.c_row_height
        ys = y + (pdf.c_cell_height+2)/2*pdf.c_row_height
        max_value = max(rx_graph + tx_graph + [1])
        draw_graph(rx_graph, lx, rx, ys, tl, max_value, 'r')
        draw_graph(tx_graph, lx, rx, ys, tl, max_value, 't')
        pdf.ln(pdf.c_row_height*(pdf.c_cell_height+0.5))

        # print domain names w/ hyperlink to whois.com, or just name
        if domset:
            for i, dom in enumerate(domset):
                txt = (dom+", ") if i < len(domset)-1 else dom  # no comma to last one
                pdf.write(pdf.c_row_height, txt, link="https://www.whois.com/whois/"+dom)
        else:
            txt = backend.get_device_ip_name(macaddr, list(ipset)[0])
            pdf.write(pdf.c_row_height, txt)
        pdf.ln(pdf.c_row_height*1.5)

        # list of IPs with hyper link back, flag and protocols list
        for ip in ipset:
            x = pdf.get_x()  # x,y (topleft) of this new cell
            y = pdf.get_y()
            pdf.set_link(conns[ip]['link_down'], y)
            # same ip addr layout as the first part
            txt = ip
            pdf.set_x( pdf.l_margin + ip_address_width - pdf.get_string_width(txt) )
            pdf.write(pdf.c_row_height, txt, conns[ip]['link_up'])

            pdf.set_x( pdf.get_x() + pdf.get_string_width('AA') )
            try:
                pathfile = '/usr/local/share/org.vync/flags/' + conns[ip]['cntr'].lower() + '.png'
                pdf.image(pathfile, y=pdf.get_y()+0.3, h=3, link="https://www.whois.com/whois/"+ip)
            except:
                pass
            # IP protocols
            # AAAAA is spacer for the flag
            pdf.set_x(pdf.l_margin + ip_address_width + pdf.get_string_width('AAAAAAA'))
            txt = ' '.join( conns[ip]['prot'] )
            pdf.write(pdf.c_row_height, txt)
            # and bytes sent/received
            txt_sent = f"  {conns[ip]['tx']:,} B".replace(",", " ")
            x_sent = pdf.w - pdf.r_margin - pdf.get_string_width(txt_sent+'↑__A')
            txt_recv = f"  {conns[ip]['rx']:,} B".replace(",", " ")
            x_recv = pdf.w - pdf.r_margin - pdf.get_string_width('↓__AAAAA') - \
                bytes_sent_width - pdf.get_string_width(txt_recv)  # AAAAA for gap between columns
            # when protocols went too far, new line
            if pdf.get_x() > x_recv - pdf.get_string_width('AAA'):
                pdf.ln(pdf.c_row_height)

            pdf.set_x( x_sent )
            pdf.set_text_color(r=255, g=0, b=0)
            pdf.write(pdf.c_row_height, "↑")
            pdf.set_text_color(0)
            pdf.write(pdf.c_row_height, txt_sent)

            pdf.set_x( x_recv )
            pdf.set_text_color(r=0, g=0, b=255)
            pdf.write(pdf.c_row_height, "↓")
            pdf.set_text_color(0)
            pdf.write(pdf.c_row_height, txt_recv)

            pdf.ln(pdf.c_row_height)  # new line

        pdf.ln(pdf.c_row_height*2.5)
        # from second group onvard ruler on every page
        pdf.c_ruler_in_header = True

    # save result
    pdf.output('/tmp/pcap2pdf-'+macaddr.replace(":", "-")+'.pdf', 'F')


# make PDF report for each device
#
def create_reports(backend, final_time, show_cnames, anonymize):

    devices = backend.get_devices()
    print(f"Will generate report for {len(devices)} devices.")

    for counter, macaddr in enumerate(devices):
        print(f"Report {counter+1}/{len(devices)} for device {macaddr}")
        create_pdf_report(backend, final_time, macaddr, show_cnames, anonymize)

    print("Done.")
    print("Reports were saved to /tmp folder.")


# check if argument is file or pipe
#
def check_file_type(pathname):
    try:
        if stat.S_ISFIFO(os.stat(pathname).st_mode):
            return 'pipe'
        if os.path.isfile(pathname):
            return 'file'
    except:
        pass
    return None


# main
#
def main():

    parser = argparse.ArgumentParser(description= \
        """Generates PDF from packet capture exported into tab delimited text file.
        If you have no idea how to use this directly, use shell script `pcap2pdf` instead.""")

    parser.add_argument('-c', '--cnames', dest='show_scnames', action='store_true',
        help="Include CNAMEs in domain list")

    parser.add_argument('-a', '--anonymize', dest='anonymize', action='store_true',
        help="Anonymize device MAC and don't show hostname")

    parser.add_argument(dest='filename', metavar='PATHNAME', type=str,
        help="/path/to/filename.csv")

    args = parser.parse_args()

    if check_file_type(args.filename):
        worker = TrafficInspector()
        reader = PacketReader(args.filename, worker)

        # start packet reader and wait until it reads the whole file
        reader.start()

        while True:
            status = reader.get_statuses()
            if status['err']:
                break
            else:
                if status['live']:
                    print("Progress:",
                        status['pkts'], "packets | Speed:",
                        status['perf'], "pkts/sec",
                        ' '*10, '\r', end='')
                    sys.stdout.flush()
                else:
                    print(f"Processed {status['pkts']} packets.", ' '*30)
                    beg = fmt_time(status['snc'], 2)
                    dur = rel_time(status['time'] - status['snc'], 2)
                    print(f"Capture starts {beg}, duration {dur}.")
                    break
            time.sleep(1)

        if status['err']:
            print("Something went wrong. Packet reader error:", status['err'])
            print("Is source file correctly exported from pcap/pcapng format?")
            quit()

        create_reports(worker, status['time'], args.show_scnames, args.anonymize)

    else:
        print(f"\nError: file/pipe '{args.filename}' not found.\n")
        quit()


if __name__ == '__main__':
    main()
