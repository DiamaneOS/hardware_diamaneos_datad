// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the daemon tells its host about the modem and the bring-up, so a failure at start is never silent.
//! The host writes each one as a line of the log at the information level. A trace carries a step, a result
//! code or a count, never a number, name or address of a phone, a SIM, a network or a peer.
use dataos_netcfg::NetError;

/// A step of the bring-up, in the order stock nicmd does them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BringupStep {
    /// Open the hardware data port (DPM Open Port).
    Port,
    /// Set the data format of the port (WDA Set Data Format).
    Format,
}

impl BringupStep {
    pub fn name(self) -> &'static str {
        match self {
            BringupStep::Port => "open port",
            BringupStep::Format => "set data format",
        }
    }
}

/// How the modem answered a bring-up step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Accepted,
    /// The result is a failure, with the QMI error code of the answer (0x46 is invalid operation).
    Refused(u16),
    /// The answer could not be read.
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trace {
    /// A route lookup with a technology preference: the technology the modem named, 0 for no answer.
    RouteTechnology(u16),
    /// The modem's data services (WDA, DPM and WDS) are all announced.
    ModemUp,
    ModemDown,
    /// A bring-up attempt starts. The count is 1 for the first after a modem start.
    BringupStart(u32),
    /// The device could not be asked for its endpoint and pipes.
    EndpointFailed(NetError),
    /// The device could not be brought up.
    LinkUpFailed(NetError),
    /// No client of the service could be had, or the request could not be sent.
    StepUnavailable(BringupStep),
    StepSent(BringupStep),
    StepAnswered(BringupStep, Answer),
    /// The step got no answer in time.
    StepTimedOut(BringupStep),
    /// A refusal or silence that was passed over, because the device was set up by an earlier attempt or daemon.
    StepPassedOver(BringupStep),
    /// The pipes or the links could not be set up.
    SetupFailed(NetError),
    /// The bring-up is complete: the daemon answers the data module that it is ready.
    Ready,
    /// The attempt is given up and the next one comes after this many milliseconds.
    RetryIn(u64),
    /// A client of the data module connected to the socket.
    ClientConnected,
    /// A connection was refused at accept.
    ClientRejected,
    /// A connection ended, and why.
    ClientClosed(&'static str),
    /// The readiness question was answered. The count is the number of answers of this kind so far.
    HelloAnswered {
        ready: bool,
        count: u32,
    },
    /// The daemon became ready or stopped being ready.
    ReadyChanged(bool),
    /// A request was refused. The count is the number of refusals of this request and code so far.
    Refused {
        request: &'static str,
        code: &'static str,
        count: u32,
    },
}

impl Trace {
    /// The line for the log, without any identifier.
    pub fn line(&self) -> String {
        match self {
            Trace::RouteTechnology(t) => {
                format!("route lookup: the modem names technology {t:#06x}")
            }
            Trace::ModemUp => "modem data services are up".into(),
            Trace::ModemDown => "modem data services are gone".into(),
            Trace::BringupStart(n) => format!("bring-up attempt {n}"),
            Trace::EndpointFailed(e) => {
                format!("bring-up: asking the device for its endpoint failed: {e:?}")
            }
            Trace::LinkUpFailed(e) => format!("bring-up: bringing the device up failed: {e:?}"),
            Trace::StepUnavailable(s) => {
                format!("bring-up: {}: no client or send failed", s.name())
            }
            Trace::StepSent(s) => format!("bring-up: {}: sent", s.name()),
            Trace::StepAnswered(s, Answer::Accepted) => format!("bring-up: {}: accepted", s.name()),
            Trace::StepAnswered(s, Answer::Refused(code)) => {
                format!(
                    "bring-up: {}: refused by the modem, QMI error {code:#x}",
                    s.name()
                )
            }
            Trace::StepAnswered(s, Answer::Malformed) => {
                format!("bring-up: {}: answer not readable", s.name())
            }
            Trace::StepTimedOut(s) => format!("bring-up: {}: no answer in time", s.name()),
            Trace::StepPassedOver(s) => {
                format!(
                    "bring-up: {}: passed over, the device was set up before",
                    s.name()
                )
            }
            Trace::SetupFailed(e) => format!("bring-up: pipes or links failed: {e:?}"),
            Trace::Ready => "bring-up done, ready".into(),
            Trace::RetryIn(ms) => format!("bring-up: next attempt in {ms} ms"),
            Trace::ClientConnected => "data module connected".into(),
            Trace::ClientRejected => "connection refused at accept".into(),
            Trace::ClientClosed(why) => format!("data module connection closed: {why}"),
            Trace::HelloAnswered { ready, count } => {
                let answer = if *ready { "ready" } else { "not ready" };
                format!("readiness question answered: {answer} (answer {count} of this kind)")
            }
            Trace::ReadyChanged(true) => "daemon is ready".into(),
            Trace::ReadyChanged(false) => "daemon is not ready".into(),
            Trace::Refused {
                request,
                code,
                count,
            } => format!("{request} refused: {code} (refusal {count} of this kind)"),
        }
    }
}

/// True for the first eight and then for every power of two: a poll that repeats every hundred
/// milliseconds writes a few dozen lines in a day, and the first ones of every kind are all there.
pub fn due(count: u32) -> bool {
    count != 0 && (count <= 8 || count.is_power_of_two())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_line_is_written_for_the_first_eight_and_then_for_each_power_of_two() {
        let written: Vec<u32> = (1..=1100).filter(|n| due(*n)).collect();
        assert_eq!(
            written,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024]
        );
        assert!(!due(0));
    }

    #[test]
    fn the_lines_name_the_step_and_the_code_and_nothing_else() {
        assert_eq!(
            Trace::StepAnswered(BringupStep::Format, Answer::Refused(0x46)).line(),
            "bring-up: set data format: refused by the modem, QMI error 0x46"
        );
        assert_eq!(
            Trace::HelloAnswered {
                ready: false,
                count: 3
            }
            .line(),
            "readiness question answered: not ready (answer 3 of this kind)"
        );
        assert_eq!(
            Trace::Refused {
                request: "route lookup",
                code: "NotReady",
                count: 1
            }
            .line(),
            "route lookup refused: NotReady (refusal 1 of this kind)"
        );
    }
}
