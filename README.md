# BEBA Controller

This is an implementation of the BEBA Controller based on the [RYU OpenFlow Controller][ryu]. This controller can be used with the BEBA Software Switch available at https://github.com/beba-eu/beba-switch

[BEBA is a European H2020 project][beba] on SDN data plane programmability. Our goal is to devise a data plane abstraction and prototype implementations for future-proof network devices capable to be repurposed with middlebox-type functions well beyond static packet forwarding, with a focus on stateful processing and packet generation.

## Running

To install the BEBA Controller on your machine:

      git clone git://github.com/beba-eu/beba-ctrl.git
      cd beba-ctrl
      python ./setup.py install

Once installed, the BEBA Controller can be executed using the `ryu-manager` command. Please refer to the [original RYU's documentation][ryu-readme] on how to use this controller.

## BEBA Extensions & App Samples

Most of the BEBA extensions (implemented as *OpenFlow Experimenter Extensions*) are implemented in [beba_v1_0_parser.py](ryu/ofproto/beba_v1_0_parser.py).
Most of the BEBA extensions (implemented as *OpenFlow Experimenter Extensions*) are implemented in [beba_v1_0_parser.py](ryu/ofproto/beba_v1_0_parser.py).

BEBA app samples can be found inside `beba-ctrl/ryu/app/beba`

# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
BEBA Software Switch is released under the Apache 2.0 License.

[beba]: http://www.beba-project.eu/
[openstate]: http://openstate-sdn.org/pub/openstate-ccr.pdf
[insp]: http://conferences.sigcomm.org/sosr/2016/papers/sosr_paper42.pdf
[ryu]: http://osrg.github.io/ryu
[ryu-readme]: https://github.com/osrg/ryu/blob/master/README.rst
